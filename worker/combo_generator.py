"""
@author: Min Du (midu@paloaltonetworks.com)
Copyright (c) 2021 Palo Alto Networks
"""

import os
import csv
import time
import math
import random
import logging
import multiprocessing

import numpy as np

from utils import misc
from utils import const
from utils.config_parser import CommonConfig


class ComboGenerator:
    """
    Combo Generator
    """
    class ComboEvalResult:
        TO_EXPEND = 0
        IS_COMBO = 1
        TO_PRUNE = 2  # and is not combo

    # NUM_PROCESS = multiprocessing.cpu_count()
    MIN_COMBOS_PER_PROCESS = 2

    def __init__(self):
        self.logger = logging.getLogger(misc.get_logger_name(__name__))
        self.logger.info('Current logging level: %s', self.logger.getEffectiveLevel())

        self.property_index_mapping = {}  # {property : id}
        self.sorted_properties = []
        self.integers_to_hit_more = {}  # {sha256: {DA : []}}
        self.min_threshold = -1
        self.integers_to_hit_less = {}  # {sha256: {DA : []}}
        self.max_threshold = -1
        self.min_combo_size = -1
        self.max_combo_size = -1
        self.pruned_cand_ints = {}
        self.hit_hashes_to_hit_more = set()
        self.hit_hashes_to_hit_less = set()
        self.start_time = 0

        # self.use_integer_subset = CommonConfig.get_use_integer_subset()
        self.properties_to_hit_more = {}
        self.properties_to_hit_less = {}
        self.pruned_cand_properties = {}

        # {combo: [sha256, ...], ...}
        self.hashes_to_hit_more_by_combo = {}
        self.hashes_to_hit_less_by_combo = {}
        # {comboA: comboB, ...}, ...} meaning that comboA is expanded from comboB,
        self.parent_combo = {}
        # {combo: cnt} means how many child combos are being checked that are expanded from this combo
        # when 'ref_cnt' is 0 we can delete its hashes in self.hashes_to_hit_**_by_combo to save memory.
        self.combo_ref_cnt = {}

        # ablation study and optimizations
        self.generation_mode = CommonConfig.get_generation_mode()
        self.do_property_sorting = False
        self.use_integer_subset = False
        self.use_multi_processing = False
        self.record_parent_hashes = False
        self.NUM_PROCESS = 1
        if self.generation_mode == 'ablation_study':
            self.do_property_sorting = CommonConfig.get_do_property_sorting()
            self.use_integer_subset = CommonConfig.get_use_integer_subset()
        else:
            self.do_property_sorting = True
            self.use_integer_subset = True
            if self.generation_mode == 'multi_processing':
                self.use_multi_processing = True
                self.NUM_PROCESS = CommonConfig.get_num_cores()
            elif self.generation_mode == 'store_parent_hits':
                self.record_parent_hashes = True
            else:
                print(f'Generation mode {self.generation_mode} unknown, please check config file.')

        self.hit_hash_folder = const.get_generated_combo_hit_hashes_folder()


    def generate_combos(self):
        summary_to_return = ['Summary: ']
        generated_combo_file = const.get_generated_combo_file()
        self.logger.info(f'Starting to generate combo file {generated_combo_file}')
        summary_to_return.append(f'Generated combos are in file {generated_combo_file}')

        # get all related configurations
        self.min_combo_size = CommonConfig.get_min_combo_size()
        self.max_combo_size = CommonConfig.get_max_combo_size()

        self.property_index_mapping = misc.get_property_index_mapping()
        # self.logger.debug(f'Loaded property_index_mapping: {self.property_index_mapping}')
        with open(const.get_all_sorted_property_file()) as fh:
            all_lines = fh.readlines()
            property_file_header, property_file_lines = all_lines[0], all_lines[1:]
            if self.do_property_sorting:
                for ln in property_file_lines:
                    self.sorted_properties.append(ln.strip().split(',')[0])
            else:
                not_sorted_property_file = const.get_not_sorted_property_file()
                if not os.path.exists(not_sorted_property_file):
                    random.seed(CommonConfig.get_random_seed())
                    random.shuffle(property_file_lines)
                    with open(not_sorted_property_file, 'w') as fh_not:
                        fh_not.write(property_file_header)
                        for ln in property_file_lines:
                            fh_not.write(ln)
                with open(not_sorted_property_file) as fh_not:
                    for ln in fh_not.readlines()[1:]:
                        self.sorted_properties.append(ln.strip().split(',')[0])

        if not self.do_property_sorting:
            random.seed(4)
            random.shuffle(self.sorted_properties)
        start_date, end_date = misc.get_start_end_date_for_combo_generation()

        if self.use_integer_subset:
            self.integers_to_hit_more = misc.load_property_integers(gt_labels=[1],
                                                                    start_date=start_date, end_date=end_date)
            self.integers_to_hit_less = misc.load_property_integers(gt_labels=[0],
                                                                    start_date=start_date, end_date=end_date)
        else:
            self.properties_to_hit_more = misc.load_property_sets(gt_labels=[1],
                                                                 start_date=start_date, end_date=end_date)
            self.properties_to_hit_less = misc.load_property_sets(gt_labels=[0],
                                                                 start_date=start_date, end_date=end_date)

        self.logger.info(f'Finished integer loading. '
                         f'Statistics: #integers_to_hit_more: {len(self.integers_to_hit_more)}; '
                         f'#integers_to_hit_less: {len(self.integers_to_hit_less)};')

        if self.record_parent_hashes:
            self.hashes_to_hit_more_by_combo['root'] = list(self.integers_to_hit_more.keys())
            self.hashes_to_hit_less_by_combo['root'] = list(self.integers_to_hit_less.keys())
            self.combo_ref_cnt['root'] = 0
            # self.logger.debug(f'record_hashes_to_check_per_combo, initial combo_ref_cnt: {self.combo_ref_cnt}')

        self.min_threshold = const.get_min_threshold()
        self.max_threshold = const.get_max_threshold()
        # self.max_threshold = int(const.get_max_threshold() * len(self.integers_to_hit_less))
        self.logger.info(f'Start combo generation, min match threshold: {self.min_threshold}; '
                         f'max match threshold: {self.max_threshold}.')
        for i in range(1, self.max_combo_size+1):
            # also need to add the ones with self.max_combo_size into pruned_set, in case duplicates are generated
            self.pruned_cand_ints[i] = set()
            self.pruned_cand_properties[i] = []

        # enumerate combos and generate
        with open(generated_combo_file, 'w') as cfp:
            csv_writer = csv.writer(cfp, delimiter=',')
            header = ['candidates', 'all-malware', 'all-benign',
                      'malware-this-hit-ratio', 'benign-this-hit-ratio', 'malware-this-hit-cnt',
                      'benign-this-hit-cnt', 'malware-total-ratio-so-far', 'benign-total-ratio-so-far',
                      'malware-total-cnt-so-far', 'benign-total-cnt-so-far', 'time-elapsed']

            csv_writer.writerow(header)
            self.start_time = time.time()

            properties_previous_step = []
            for new_property in self.sorted_properties:
                self.logger.info('Adding new property %s', new_property)
                if self.record_parent_hashes:
                    self.parent_combo[new_property] = 'root'
                    self.combo_ref_cnt['root'] += 1
                    self.logger.debug(f'record_hashes_to_check_per_combo, adding new property {new_property},'
                                      f'combo_ref_cnt: {self.combo_ref_cnt}')

                property_list = [new_property] + properties_previous_step
                candidates = [[b] for b in property_list]
                property_id_mapping = dict((f, i) for i, f in enumerate(property_list))

                while len(candidates) > 0:
                    new_candidates_potential = []
                    candidates_to_eval = []
                    for combo_candidate in candidates:
                        if combo_candidate[0] in properties_previous_step:
                            break
                        candidates_to_eval.append(combo_candidate)
                    self.logger.info(f'--Time elapsed: {time.time()-self.start_time}, '
                                     f'#combos to evaluate next: {len(candidates_to_eval)}')
                    if len(candidates_to_eval) == 0:
                        break
                    if self.use_multi_processing:
                        start_time = time.time()
                        result_array = self.multi_processing(self.check_one_candidate, candidates_to_eval)
                        self.logger.debug(f'++Time taken to eval each combo: '
                                          f'{(time.time()-start_time) / len(candidates_to_eval)}, '
                                          f'One round of evaluation done. Evaluated candidates: {candidates_to_eval}')
                        new_candidates_potential += \
                            self.handle_eval_results(candidates_to_eval, result_array, property_id_mapping, property_list,
                                                     csv_writer, cfp)

                        result_array = self.multi_processing(self.check_candidate_validity, new_candidates_potential)
                        candidates = []
                        for idx, nc in enumerate(new_candidates_potential):
                            if result_array[idx] > 0:
                                candidates.append(nc)
                    else:
                        for cc in candidates_to_eval:
                            eval_result = self.check_one_candidate_single_process(cc)
                            self.logger.debug(f'cc: {cc}, eval_result: {eval_result}')
                            new_candidates_potential += \
                                self.handle_eval_results([cc], [eval_result], property_id_mapping, property_list,
                                                         csv_writer, cfp)
                        candidates = []
                        for nc in new_candidates_potential:
                            if not self.is_pruned(nc):
                                candidates.append(nc)
                                if self.record_parent_hashes:
                                    # self.logger.debug(f'record_hashes_to_check_per_combo, add 1 to ref cnt of '
                                    #                   f'{self.parent_combo["-".join(sorted(nc))]} '
                                    #                   f'for evaluating its child combo {"-".join(nc)}')
                                    self.combo_ref_cnt[self.parent_combo['-'.join(sorted(nc))]] += 1

                if not self.is_pruned([new_property]):
                    properties_previous_step.append(new_property)

        return summary_to_return

    def multi_processing(self, func, candidates_to_handle):
        result_array = []
        if len(candidates_to_handle) > 0:
            processes = []
            result_array = multiprocessing.Array('i', range(len(candidates_to_handle)))
            num_candidates_per_process = self.get_num_candidates_per_process(len(candidates_to_handle))
            candidates_to_handle = np.asarray(candidates_to_handle)
            for idx in range(0, len(candidates_to_handle), num_candidates_per_process):
                idx_range = [x for x in
                             range(idx, min(len(candidates_to_handle), idx + num_candidates_per_process))]
                random.shuffle(idx_range)
                new_candidates = candidates_to_handle[idx_range]
                p = multiprocessing.Process(target=func, args=(new_candidates, result_array, idx_range))
                processes.append(p)
                p.start()
            for process in processes:
                process.join()
        return result_array

    def get_num_candidates_per_process(self, num_candidates_to_handle):
        num_processes = max(
            min(self.NUM_PROCESS, math.ceil(num_candidates_to_handle / self.MIN_COMBOS_PER_PROCESS)), 1)
        num_candidates_per_process = math.ceil(num_candidates_to_handle / num_processes)
        self.logger.info(f'#processes: {num_processes}, #candidates per process: {num_candidates_per_process}')
        return num_candidates_per_process

    def check_candidate_validity(self, candidates, result_array, idx_range):
        for idx, nc in enumerate(candidates):
            this_idx = idx_range[idx]
            if self.is_pruned(nc):
                result_array[this_idx] = 0
            else:
                result_array[this_idx] = 1

    def handle_eval_results(self, candidates, result_array, property_id_mapping, property_list, csv_writer, cfp):
        new_candidates_potential = []
        for idx, combo in enumerate(candidates):
            state = result_array[idx]
            if state == self.ComboEvalResult.TO_EXPEND:
                self.logger.debug(f'Expanding {combo}.')
                if len(combo) < self.max_combo_size:
                    candidates_to_check = self.get_new_candidates(combo, property_id_mapping=property_id_mapping,
                                                                  property_list=property_list)
                    new_candidates_potential += candidates_to_check
            elif state == self.ComboEvalResult.IS_COMBO:
                self.logger.info(f'generated combo {combo}')
                tp_hit_hashes, fp_hit_hashes = set(), set()
                if self.use_integer_subset:
                    full_int = self._get_integer(combo)
                    self.pruned_cand_ints[len(combo)].add(full_int)
                    # count unique malware hit now
                    # count unique malware hit now
                    if not self.record_parent_hashes:
                        tp_hit_hashes = \
                            self.get_hit_hashes(full_int, self.integers_to_hit_more,
                                               hit_hashes_already = self.hit_hashes_to_hit_more)
                        fp_hit_hashes = \
                            self.get_hit_hashes(full_int, self.integers_to_hit_less,
                                               hit_hashes_already = self.hit_hashes_to_hit_less)
                        this_hit_cnt_to_hit_more = len(tp_hit_hashes)
                        this_hit_cnt_to_hit_less = len(fp_hit_hashes)
                    else:
                        parent_combo = self.parent_combo['-'.join(sorted(combo))]
                        self.logger.debug(f'record_hashes_to_check_per_combo, generated new combo {combo}, '
                                          f'its parent combo is {parent_combo}, '
                                          f'#hashes_to_hit_more: {len(self.hashes_to_hit_more_by_combo[parent_combo])}, '
                                          f'#hashes_to_hit_less: {len(self.hashes_to_hit_less_by_combo[parent_combo])}')
                        tp_hit_hashes = \
                            self.get_hit_hashes(full_int, self.integers_to_hit_more,
                                               hit_hashes_already = self.hit_hashes_to_hit_more,
                                               hashes_to_check_by_combo=self.hashes_to_hit_more_by_combo[parent_combo])
                        fp_hit_hashes = \
                            self.get_hit_hashes(full_int, self.integers_to_hit_less,
                                               hit_hashes_already = self.hit_hashes_to_hit_less,
                                               hashes_to_check_by_combo=self.hashes_to_hit_less_by_combo[parent_combo])
                        this_hit_cnt_to_hit_more = len(tp_hit_hashes)
                        this_hit_cnt_to_hit_less = len(fp_hit_hashes)
                        self.check_and_cleanup_hashes_by_combo(combo)
                    self.logger.debug(f'this_hit_cnt_to_hit_more: {this_hit_cnt_to_hit_more}, this_hit_cnt_to_hit_less: {this_hit_cnt_to_hit_less}')
                    total_cnt_to_hit_more = len(self.integers_to_hit_more)
                    total_cnt_to_hit_less = len(self.integers_to_hit_less)
                else:
                    combo = set(combo)
                    self.pruned_cand_properties[len(combo)].append(combo)
                    tp_hit_hashes = self.get_hit_hashes_by_properties(combo, self.properties_to_hit_more, self.hit_hashes_to_hit_more)
                    fp_hit_hashes = self.get_hit_hashes_by_properties(combo, self.properties_to_hit_less, self.hit_hashes_to_hit_less)
                    this_hit_cnt_to_hit_more = len(tp_hit_hashes)
                    this_hit_cnt_to_hit_less = len(fp_hit_hashes)
                    total_cnt_to_hit_more = len(self.properties_to_hit_more)
                    total_cnt_to_hit_less = len(self.properties_to_hit_less)

                ###
                with open(os.path.join(self.hit_hash_folder, f'{"-".join(sorted(combo))}.tp'), 'w') as fh:
                    for hh in tp_hit_hashes:
                        fh.write(f'{hh}\n')
                with open(os.path.join(self.hit_hash_folder, f'{"-".join(sorted(combo))}.fp'), 'w') as fh:
                    for hh in fp_hit_hashes:
                        fh.write(f'{hh}\n')
                ###


                sofar_hit_cnt_to_hit_more = len(self.hit_hashes_to_hit_more)
                sofar_hit_cnt_to_hit_less = len(self.hit_hashes_to_hit_less)

                one_row = ['-'.join(sorted(combo)), total_cnt_to_hit_more, total_cnt_to_hit_less,
                           f'{this_hit_cnt_to_hit_more * 100 / total_cnt_to_hit_more}',
                           f'{this_hit_cnt_to_hit_less * 100 / total_cnt_to_hit_less}',
                           this_hit_cnt_to_hit_more, this_hit_cnt_to_hit_less,
                           f'{sofar_hit_cnt_to_hit_more * 100 / total_cnt_to_hit_more: .3f}',
                           f'{sofar_hit_cnt_to_hit_less * 100 / total_cnt_to_hit_less: .3f}',
                           f'{sofar_hit_cnt_to_hit_more}', f'{sofar_hit_cnt_to_hit_less}',
                           f'{time.time() - self.start_time: .3f}']
                csv_writer.writerow(one_row)
                cfp.flush()
            else:
                self.logger.info(f'Combo {combo} did not hit enough hashes_to_hit_more, add it to prune list')
                if self.use_integer_subset:
                    full_int = self._get_integer(combo)
                    self.pruned_cand_ints[len(combo)].add(full_int)
                    if self.record_parent_hashes:
                        self.logger.debug(f'record_hashes_to_check_per_combo, pruning combo {combo}')
                        self.check_and_cleanup_hashes_by_combo(combo)
                else:
                    self.pruned_cand_properties[len(combo)].append(set(combo))
        return new_candidates_potential

    def check_and_cleanup_hashes_by_combo(self, child_combo):
        # free memory
        parent_combo = self.parent_combo['-'.join(sorted(child_combo))]
        self.logger.debug(f'record_hashes_to_check_per_combo, to cleanup for combo {child_combo}, '
                          f'its parent combo is {parent_combo}, '
                          f'self.combo_ref_cnt[parent_combo]: {self.combo_ref_cnt[parent_combo]}')
        self.combo_ref_cnt[parent_combo] -= 1
        del self.parent_combo['-'.join(sorted(child_combo))]
        if self.combo_ref_cnt[parent_combo] == 0 and parent_combo != 'root':
            del self.hashes_to_hit_more_by_combo[parent_combo]
            del self.hashes_to_hit_less_by_combo[parent_combo]
            self.logger.debug(f'record_hashes_to_check_per_combo, deleted hashes for combo {parent_combo}')

    def check_one_candidate(self, combo_candidate, eval_result, idx_range):
        for idx, cc in enumerate(combo_candidate):
            this_idx = idx_range[idx]
            full_int = self._get_integer(cc)
            if self.hit_many(full_int, self.integers_to_hit_more, self.min_threshold-1):
                if self.hit_many(full_int, self.integers_to_hit_less, self.max_threshold):
                    eval_result[this_idx] = self.ComboEvalResult.TO_EXPEND
                else:  # generated one
                    eval_result[this_idx] = self.ComboEvalResult.IS_COMBO
            else:
                eval_result[this_idx] = self.ComboEvalResult.TO_PRUNE

    def check_one_candidate_single_process(self, cc):
        if self.use_integer_subset:
            full_int = self._get_integer(cc)
            if not self.record_parent_hashes:
                if self.hit_many(full_int, self.integers_to_hit_more, self.min_threshold-1):
                    if self.hit_many(full_int, self.integers_to_hit_less, self.max_threshold):
                        return self.ComboEvalResult.TO_EXPEND
                    else:  # generated one
                        return self.ComboEvalResult.IS_COMBO
                else:
                    return self.ComboEvalResult.TO_PRUNE
            else:
                combo_str = '-'.join(sorted(cc))
                hashes_to_hit_more = self.get_hit_hashes(full_int, self.integers_to_hit_more,
                                                         self.hashes_to_hit_more_by_combo[self.parent_combo[combo_str]])
                if len(hashes_to_hit_more) > self.min_threshold-1:
                    hashes_to_hit_less = self.get_hit_hashes(full_int, self.integers_to_hit_less,
                                                             self.hashes_to_hit_less_by_combo[self.parent_combo[combo_str]])
                    if len(hashes_to_hit_less) > self.max_threshold:
                        self.hashes_to_hit_more_by_combo[combo_str] = hashes_to_hit_more
                        self.hashes_to_hit_less_by_combo[combo_str] = hashes_to_hit_less
                        self.combo_ref_cnt[combo_str] = 0
                        self.logger.debug(f'record_hashes_to_check_per_combo, generated hit_hashes for combo {cc}, '
                                          f'#hashes_to_hit_more_by_combo[combo]: '
                                          f'{len(self.hashes_to_hit_more_by_combo[combo_str])}, '
                                          f'#hashes_to_hit_less_by_combo[combo]: '
                                          f'{len(self.hashes_to_hit_less_by_combo[combo_str])}')
                        return self.ComboEvalResult.TO_EXPEND
                    else:
                        return self.ComboEvalResult.IS_COMBO
                else:
                    return self.ComboEvalResult.TO_PRUNE
        else:
            # full_int = self._get_integer(cc)
            cc = set(cc)
            if not self.record_parent_hashes:
                if self.hit_many_by_properties(cc, self.properties_to_hit_more, self.min_threshold-1):
                    if self.hit_many_by_properties(cc, self.properties_to_hit_less, self.max_threshold):
                        return self.ComboEvalResult.TO_EXPEND
                    else:  # generated one
                        return self.ComboEvalResult.IS_COMBO
                else:
                    return self.ComboEvalResult.TO_PRUNE

    def hit_many(self, this_int, all_ints_to_check, max_cnt, hashes_to_check_by_combo=None):
        if hashes_to_check_by_combo is None:
            hashes_to_check_by_combo = list(all_ints_to_check.keys())
        cnt = 0
        for sha256 in hashes_to_check_by_combo:
            integer = all_ints_to_check[sha256]
            if self.first_in_second(this_int, integer):
                cnt += 1
                # if self._get_property_combo(this_int) == {'23'}:
                #     print(f'{sha256}, integer: {integer}, properties: {self._get_property_combo(integer)}')
                if cnt > max_cnt:  # todo: uncomment after debugging
                    return True
        # print(f'property_set_to_check: {self._get_property_combo(this_int)}, hit_count: {cnt}, max_cnt: {max_cnt}')
        # if cnt > max_cnt:  # todo: delete after debugging
        #     return True
        return False

    def hit_many_by_properties(self, property_set_to_check, all_property_sets_to_check, max_cnt):
        cnt = 0
        for sha256, property_set in all_property_sets_to_check.items():
            # self.logger.debug(f'check if property_set_to_check {property_set_to_check} a subset of {property_set}')
            if self.first_in_second_properties(property_set_to_check, property_set):
                cnt += 1
                # if property_set_to_check == {'23'}:
                #     print(f'{sha256}, properties: {property_set}, integer: {self._get_integer(property_set)}')
                #     print(f'fcea97e494944748e2e0bef5817f49708518aea11228806674e407f627c824b7, properties: {all_property_sets_to_check["fcea97e494944748e2e0bef5817f49708518aea11228806674e407f627c824b7"]}')
                if cnt > max_cnt:  # todo: uncomment after debugging
                    return True
        # print(f'property_set_to_check: {property_set_to_check}, hit_count: {cnt}, max_cnt: {max_cnt}')
        # if cnt > max_cnt:  # todo: delete after debugging
        #     return True
        return False

    # def get_hit_count(self, full_int, all_ints_to_check, hit_hashes_already, hashes_to_check_by_combo=None):
    #     this_hit_hashes = self.get_hit_hashes(full_int, all_ints_to_check,
    #                                           hashes_to_check_by_combo=hashes_to_check_by_combo)
    #     hit_hashes_already.update(this_hit_hashes)
    #     return len(this_hit_hashes)

    def get_hit_hashes(self, full_int, all_ints_to_check, hashes_to_check_by_combo=None, hit_hashes_already=None):
        if hashes_to_check_by_combo is None:
            hashes_to_check_by_combo = list(all_ints_to_check.keys())
        hit_hashes = set()
        self.logger.debug(f'len(hashes_to_check_by_combo): {len(hashes_to_check_by_combo)}')
        for sha256 in hashes_to_check_by_combo:
            integer = all_ints_to_check[sha256]
            if self.first_in_second(full_int, integer):
                hit_hashes.add(sha256)
        if hit_hashes_already is not None:
            hit_hashes_already.update(hit_hashes)
        return hit_hashes

    def get_hit_hashes_by_properties(self, property_set_to_check, all_property_sets_to_check, hit_hashes_already):
        hit_count = 0
        hit_hashes = set()
        for sha256, property_set in all_property_sets_to_check.items():
            if self.first_in_second_properties(property_set_to_check, property_set):
                hit_count += 1
                hit_hashes.add(sha256)
                hit_hashes_already.add(sha256)
        return hit_hashes

    def get_new_candidates(self, combo, property_id_mapping, property_list):
        cur_candidate = combo[-1]
        cur_id = property_id_mapping[cur_candidate]
        ret = []
        for property in property_list[cur_id+1:]:
            new_candidate = list(combo) + [property]
            if self.record_parent_hashes:
                self.parent_combo['-'.join(sorted(new_candidate))] = '-'.join(sorted(combo))
                # self.logger.debug(f'record_hashes_to_check_per_combo, '
                #                   f'added parent combo {"-".join(combo)} for combo {"-".join(new_candidate)}')
            ret.append(new_candidate)
        return ret

    def is_pruned(self, new_candidate):
        if self.use_integer_subset:
            new_int = self._get_integer(new_candidate)
            for length, ints in self.pruned_cand_ints.items():
                if length > len(new_candidate):
                    continue
                for candidate_int in self.pruned_cand_ints[length]:
                    if self.first_in_second(candidate_int, new_int):
                        # self.logger.debug(f'Prune combo {new_cand} because it is a superset of previous pruned combo ')
                                          # f'{self._get_property_combo(cand_int)}')
                        return True
            return False
        else:
            for length, property_set_lists in self.pruned_cand_properties.items():
                if length > len(new_candidate):
                    continue
                for property_set in property_set_lists:
                    if self.first_in_second_properties(property_set, new_candidate):
                        self.logger.debug(f'Prune combo {new_candidate} because it is a superset of previous pruned combo '
                                          f'{property_set}')
                        return True
            return False

    def first_in_second(self, first_int, second_int):
        return first_int & second_int == first_int

    def first_in_second_properties(self, first_set, second_set):
        return first_set.issubset(second_set)

    def _get_integer(self, properties):
        ret = 0
        for b in properties:
            # b = misc.get_property_from_combo_property(b)
            if b not in self.property_index_mapping:
                return -1
            ret |= 1 << self.property_index_mapping[b]
        return ret

    def _get_property_combo(self, integer):
        ret = set()
        for property, idx in self.property_index_mapping.items():
            if integer & (1 << idx):
                ret.add(property)
        return ret
