"""
@author: Min Du (midu@paloaltonetworks.com)
Copyright (c) 2021 Palo Alto Networks
"""

import os
import csv
import time
import copy
import logging

from utils import misc
from utils import const
from utils.config_parser import CommonConfig


class ComboSelector:

    def __init__(self):
        self.logger = logging.getLogger(misc.get_logger_name(__name__))
        self.logger.info('Current logging level: %s', self.logger.getEffectiveLevel())
        generated_combo_file = const.get_generated_combo_file()
        if CommonConfig.get_combo_selection_approach() == 'threshold':
            self.combo_file_to_select = const.get_sorted_combo_file(generated_combo_file)
        else:
            self.combo_file_to_select = generated_combo_file
        self.hit_hash_folder = const.get_generated_combo_hit_hashes_folder()
        self.selected_combo_file = const.get_selected_combo_file(self.combo_file_to_select)
        self.malware_count = -1
        self.benign_count = -1


    def select_combos(self):
        summary_to_return = ['Summary: ']
        self.logger.info(f'Starting to select combo file {self.combo_file_to_select}')
        summary_to_return.append(f'Selected combos are in file {self.selected_combo_file}')

        if not os.path.exists(self.combo_file_to_select):
            error = f'Combo file to select does not exist: {self.combo_file_to_select}'
            self.logger.error(error)
            summary_to_return.append(error)
            return summary_to_return

        sorted_combo_list = []
        combo_record_dict = {}
        tp_hits, fp_hits = {}, {}
        with open(self.combo_file_to_select) as fh_in, open(self.selected_combo_file, 'w') as fh_out:
            csvwriter = csv.writer(fh_out, delimiter=',')
            all_in_lines = fh_in.readlines()
            header = all_in_lines[0].strip().split(',')
            csvwriter.writerow(header+['tp-sofar', 'fp-sofar', 'added-score', 'overall-score', 'time-elapsed'])
            for ln in all_in_lines[1:]:
                record = ln.strip().split(',')
                combo = record[0]
                combo_record_dict[combo] = record
                self.malware_count = int(record[const.ComboColumnAttributes.ALL_MALWARE])
                self.benign_count = int(record[const.ComboColumnAttributes.ALL_BENIGN])
                print(f'all_malware: {self.malware_count}, all_benign: {self.benign_count}')
                correct_tmp, incorrect_tmp = self.get_hits(combo)
                if correct_tmp is None:
                    break
                tp_hits[combo], fp_hits[combo] = correct_tmp, incorrect_tmp
                sorted_combo_list.append(combo)
                print('combo: ', combo, 'tp_hits[combo]', len(tp_hits[combo]), 'fp_hits[combo]', len(fp_hits[combo]))

            if CommonConfig.get_combo_selection_approach() == 'threshold':
                start_time = time.time()
                tp_hits_sofar, fp_hits_sofar = set(), set()
                for combo in sorted_combo_list:
                    tp, fp = tp_hits[combo], fp_hits[combo]
                    added_tp_cnt = len(tp-tp_hits_sofar)
                    added_fp_cnt = len(fp-fp_hits_sofar)
                    if added_tp_cnt == 0:
                        continue
                    tp_hits_sofar.update(tp)
                    fp_hits_sofar.update(fp)
                    if added_fp_cnt == 0:
                        if added_tp_cnt > 100:
                            csvwriter.writerow(record + [len(tp_hits_sofar)/(self.malware_count+1e-07),
                                                         len(fp_hits_sofar)/(self.benign_count+1e-07),
                                                         self.get_selection_score(added_tp_cnt, added_fp_cnt),
                                                         self.get_selection_score(len(tp_hits_sofar),
                                                                                  len(fp_hits_sofar)),
                                                         time.time()-start_time])
                            fh_out.flush()

                    elif added_tp_cnt/added_fp_cnt > CommonConfig.get_selection_threshold():
                        csvwriter.writerow(record+[len(tp_hits_sofar)*100/(self.malware_count+1e-07),
                                                   len(fp_hits_sofar)*100/(self.benign_count+1e-07),
                                                   self.get_selection_score(added_tp_cnt, added_fp_cnt),
                                                   self.get_selection_score(len(tp_hits_sofar), len(fp_hits_sofar)),
                                                   time.time()-start_time])
                        fh_out.flush()

            elif CommonConfig.get_combo_selection_approach() == 'best-remaining':
                # choose the one that if added, adds most overall mfibf score from remaining every time
                start_time = time.time()
                tp_hits_sofar, fp_hits_sofar = set(), set()
                remaining_combos = set(sorted_combo_list)
                while len(remaining_combos) > 0:
                    max_combo = ''
                    max_heuristic_score = -1
                    for_loop_start_time = time.time()
                    print(f'start another for loop, len(remaining_combos): {len(remaining_combos)}')
                    for combo in remaining_combos:
                        inside_for_loop_start_time = time.time()
                        if tp_hits_sofar.intersection(tp_hits[combo]) == tp_hits[combo]:
                            continue
                        tmp_tp, tmp_fp = copy.deepcopy(tp_hits[combo]), copy.deepcopy(fp_hits[combo])
                        tmp_tp.update(tp_hits_sofar)
                        tmp_fp.update(fp_hits_sofar)
                        total_corrects_cnt_if_adding_combo = len(tmp_tp)
                        total_incorrects_cnt_if_adding_combo = len(tmp_fp)
                        heuristic_score = self.get_selection_score(total_corrects_cnt_if_adding_combo,
                                                                   total_incorrects_cnt_if_adding_combo)
                        # print('combo', combo, 'heuristic_score', heuristic_score,
                        #       'max_heuristic_score', max_heuristic_score)
                        if heuristic_score > max_heuristic_score:
                            max_heuristic_score = heuristic_score
                            max_combo = combo
                        # print(f'inside for loop, one iteration takes time: {time.time()-inside_for_loop_start_time}')
                    if max_combo == '':
                        break
                    print(f'for loops takes time: {time.time()-for_loop_start_time}, len(remaining_combos): {len(remaining_combos)}')
                    # write max combo in this round to file
                    print('max_combo', max_combo, 'max_heuristic_score', max_heuristic_score,
                          'len(correct_hits[max_combo])', len(tp_hits[max_combo]),
                          'len(fp_hits[max_combo])', len(fp_hits[max_combo]))
                    added_tp_cnt = len(tp_hits[max_combo] - tp_hits_sofar)
                    added_fp_cnt = len(fp_hits[max_combo] - fp_hits_sofar)
                    tp_hits_sofar.update(tp_hits[max_combo])
                    fp_hits_sofar.update(fp_hits[max_combo])
                    print(f'len(tp_hits_sofar): {len(tp_hits_sofar)}, self.malware_count: {self.malware_count}')
                    csvwriter.writerow(combo_record_dict[max_combo] +
                                       [len(tp_hits_sofar) * 100 / (self.malware_count),
                                        len(fp_hits_sofar) * 100 / (self.benign_count),
                                        self.get_selection_score(added_tp_cnt, added_fp_cnt),
                                        self.get_selection_score(len(tp_hits_sofar), len(fp_hits_sofar)),
                                        time.time()-start_time])
                    fh_out.flush()
                    remaining_combos.remove(max_combo)

        return summary_to_return

    def get_selection_score(self, corrects_cnt, incorrects_cnt):
        if CommonConfig.get_combo_sorting_criteria() == 'mfibf':
            return corrects_cnt / (incorrects_cnt + 1e-07)
        elif CommonConfig.get_combo_sorting_criteria() == 'f05':
            tp, fp = corrects_cnt, incorrects_cnt
            fn = self.malware_count - tp  # total #malware - tp
            heuristic_score = (1 + 0.5 * 0.5) * tp / ((1 + 0.5 * 0.5) * tp + 0.5 * 0.5 * fn + fp + 1e-07)
            return heuristic_score

    def get_hits(self, combo):
        tp, fp = set(), set()
        with open(os.path.join(self.hit_hash_folder, f'{combo}.tp')) as fh:
            for ln in fh.readlines():
                tp.add(ln.strip())
        with open(os.path.join(self.hit_hash_folder, f'{combo}.fp')) as fh:
            for ln in fh.readlines():
                fp.add(ln.strip())
        return tp, fp
