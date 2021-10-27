"""
@author: Min Du (midu@paloaltonetworks.com)
Copyright (c) 2021 Palo Alto Networks
"""

import os
import csv
import time
import random
import logging

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

    def __init__(self):
        self.logger = logging.getLogger(misc.get_logger_name(__name__))
        self.logger.info('Current logging level: %s', self.logger.getEffectiveLevel())

        self.property_index_mapping = {}  # {property : id}
        self.sorted_properties = []
        self.min_threshold = -1
        self.max_threshold = -1
        self.min_combo_size = -1
        self.max_combo_size = -1
        self.pruned_cand_ints = {}
        self.malware_hit_hashes_sofar = set()
        self.benign_hit_hashes_sofar = set()
        self.start_time = 0

        self.malware_property_sets = {}
        self.benign_property_sets = {}
        self.pruned_cand_properties = {}

        # {combo: [sha256, ...], ...}
        self.hashes_to_hit_more_by_combo = {}
        self.hashes_to_hit_less_by_combo = {}

        self.do_property_sorting = True

        self.property_hashes = {'malware': {}, 'benign': {}}
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
        self.benign_property_sets = misc.load_property_sets(gt_labels=[0],
                                                            start_date=start_date, end_date=end_date)
        self.malware_property_sets = misc.load_property_sets(gt_labels=[1],
                                                             start_date=start_date, end_date=end_date)

        for sha256, bhr_set in self.malware_property_sets.items():
            self.logger.debug(f'sha256: {sha256}, bhr_set: {bhr_set}')

        self.logger.info(f'Finished data loading. '
                         f'Statistics: #properties_to_hit_more: {len(self.malware_property_sets)}; '
                         f'#properties_to_hit_less: {len(self.benign_property_sets)};')
        for sha256, bhrs in self.malware_property_sets.items():
            for bhr in bhrs:
                if bhr not in self.property_hashes['malware']:
                    self.property_hashes['malware'][bhr] = set()
                self.property_hashes['malware'][bhr].add(sha256)
        for sha256, bhrs in self.benign_property_sets.items():
            for bhr in bhrs:
                if bhr not in self.property_hashes['benign']:
                    self.property_hashes['benign'][bhr] = set()
                self.property_hashes['benign'][bhr].add(sha256)

        self.min_threshold = const.get_min_threshold()
        self.max_threshold = const.get_max_threshold()
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

                if not self.is_pruned([new_property]):
                    properties_previous_step.append(new_property)

        return summary_to_return

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
                combo = set(combo)
                self.pruned_cand_properties[len(combo)].append(combo)
                tp_hit_hashes = self.get_hit_hashes(combo, self.property_hashes['malware'])
                self.malware_hit_hashes_sofar.update(tp_hit_hashes)
                this_malware_hit_count = len(tp_hit_hashes)

                fp_hit_hashes = self.get_hit_hashes(combo, self.property_hashes['benign'])
                self.benign_hit_hashes_sofar.update(fp_hit_hashes)
                this_benign_hit_count = len(fp_hit_hashes)

                ###
                with open(os.path.join(self.hit_hash_folder, f'{"-".join(sorted(combo))}.tp'), 'w') as fh:
                    for hh in tp_hit_hashes:
                        fh.write(f'{hh}\n')
                with open(os.path.join(self.hit_hash_folder, f'{"-".join(sorted(combo))}.fp'), 'w') as fh:
                    for hh in fp_hit_hashes:
                        fh.write(f'{hh}\n')
                ###

                total_malware_hit_count = len(self.malware_property_sets)
                total_benign_hit_count = len(self.benign_property_sets)

                sofar_hit_cnt_to_hit_more = len(self.malware_hit_hashes_sofar)
                sofar_hit_cnt_to_hit_less = len(self.benign_hit_hashes_sofar)

                one_row = ['-'.join(sorted(combo)), total_malware_hit_count, total_benign_hit_count,
                           f'{this_malware_hit_count * 100 / total_malware_hit_count}',
                           f'{this_benign_hit_count * 100 / total_benign_hit_count}',
                           this_malware_hit_count, this_benign_hit_count,
                           f'{sofar_hit_cnt_to_hit_more * 100 / total_malware_hit_count: .3f}',
                           f'{sofar_hit_cnt_to_hit_less * 100 / total_benign_hit_count: .3f}',
                           f'{sofar_hit_cnt_to_hit_more}', f'{sofar_hit_cnt_to_hit_less}',
                           f'{time.time() - self.start_time: .3f}']
                csv_writer.writerow(one_row)
                cfp.flush()
            else:
                self.logger.info(f'Combo {combo} did not hit enough hashes_to_hit_more, add it to prune list')
                self.pruned_cand_properties[len(combo)].append(set(combo))
        return new_candidates_potential

    def check_one_candidate_single_process(self, cc):
        # full_int = self._get_integer(cc)
        cc = set(cc)
        if self.hit_many_by_properties(cc, self.property_hashes['malware'], self.min_threshold-1):
            if self.hit_many_by_properties(cc, self.property_hashes['benign'], self.max_threshold):
                return self.ComboEvalResult.TO_EXPEND
            else:  # generated one
                return self.ComboEvalResult.IS_COMBO
        else:
            return self.ComboEvalResult.TO_PRUNE

    def hit_many_by_properties(self, property_set_to_check, property_hashes, max_cnt):
        hit_count = len(self.get_hit_hashes(property_set_to_check, property_hashes))
        self.logger.debug(f'property_set_to_check: {property_set_to_check}, hit_count: {hit_count}, max_cnt: {max_cnt}')
        return hit_count > max_cnt

    def get_hit_hashes(self, candidate, property_hashes):
        hit_hashes = set()
        for k in candidate:
            if k in property_hashes:
                if len(hit_hashes) == 0:
                    hit_hashes = property_hashes[k]
                else:
                    hit_hashes = set.intersection(hit_hashes, property_hashes[k])
        return hit_hashes

    def get_new_candidates(self, combo, property_id_mapping, property_list):
        cur_candidate = combo[-1]
        cur_id = property_id_mapping[cur_candidate]
        ret = []
        for property in property_list[cur_id+1:]:
            new_candidate = list(combo) + [property]
            ret.append(new_candidate)
        return ret

    def is_pruned(self, new_candidate):
        for length, property_set_lists in self.pruned_cand_properties.items():
            if length > len(new_candidate):
                continue
            for property_set in property_set_lists:
                if self.first_in_second_properties(property_set, new_candidate):
                    self.logger.debug(f'Prune combo {new_candidate} because it is a superset of previous pruned combo '
                                      f'{property_set}')
                    return True
        return False

    def first_in_second_properties(self, first_set, second_set):
        return first_set.issubset(second_set)

    def _get_property_combo(self, integer):
        ret = []
        for property, idx in self.property_index_mapping.items():
            if integer & (1 << idx):
                ret.append(property)
        return ret
