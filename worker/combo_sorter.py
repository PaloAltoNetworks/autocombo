"""
@author: Min Du (midu@paloaltonetworks.com)
Copyright (c) 2021 Palo Alto Networks
"""

import os
import logging
import numpy as np

from utils import misc
from utils import const
from utils.config_parser import CommonConfig


class ComboSorter:

    def __init__(self):
        self.logger = logging.getLogger(misc.get_logger_name(__name__))
        self.logger.info('Current logging level: %s', self.logger.getEffectiveLevel())

        self.generated_combo_file = const.get_generated_combo_file()
        self.sorted_combo_file = const.get_sorted_combo_file(combo_file_to_sort=self.generated_combo_file)
        self.sorting_heuristic_score = {}   # {combo: score}

    def sort_combos(self):
        summary_to_return = ['Summary: ']
        self.logger.info(f'Starting to sort combo file {self.generated_combo_file}')
        summary_to_return.append(f'Sorted combos are in file {self.sorted_combo_file}')

        if not os.path.exists(self.generated_combo_file):
            error = f'Combo file to sort does not exist: {self.generated_combo_file}'
            self.logger.error(error)
            summary_to_return.append(error)
            return summary_to_return

        with open(self.generated_combo_file) as fh_in, open(self.sorted_combo_file, 'w') as fh_out:
            all_in_lines = fh_in.readlines()
            header = all_in_lines[0].strip().split(',')
            fh_out.write(f'{header[const.ComboColumnAttributes.COMBO]},'
                         f'{header[const.ComboColumnAttributes.ALL_MALWARE]},'
                         f'{header[const.ComboColumnAttributes.ALL_BENIGN]},'
                         f'{header[const.ComboColumnAttributes.THIS_HIT_RATIO_TO_HIT_MORE]},'
                         f'{header[const.ComboColumnAttributes.THIS_HIT_RATIO_TO_HIT_LESS]},'
                         f'{header[const.ComboColumnAttributes.THIS_HIT_CNT_TO_HIT_MORE]},'
                         f'{header[const.ComboColumnAttributes.THIS_HIT_CNT_TO_HIT_LESS]},'
                         f'{header[const.ComboColumnAttributes.TIME_ELAPSED]},'
                         f'heuristic-score\n')
            combo_records = {}
            for ln in all_in_lines[1:]:
                record = ln.strip().split(',')
                combo = record[const.ComboColumnAttributes.COMBO]
                this_hit_ratio_to_hit_more = record[const.ComboColumnAttributes.THIS_HIT_RATIO_TO_HIT_MORE]
                this_hit_ratio_to_hit_less = record[const.ComboColumnAttributes.THIS_HIT_RATIO_TO_HIT_LESS]
                this_hit_cnt_to_hit_more = record[const.ComboColumnAttributes.THIS_HIT_CNT_TO_HIT_MORE]
                this_hit_cnt_to_hit_less = record[const.ComboColumnAttributes.THIS_HIT_CNT_TO_HIT_LESS]
                time_elapsed = record[const.ComboColumnAttributes.TIME_ELAPSED]
                self.calculate_heuristic_score(combo, this_hit_ratio_to_hit_more, this_hit_ratio_to_hit_less,
                                               this_hit_cnt_to_hit_more, this_hit_cnt_to_hit_less)
                combo_records[combo] = [combo, record[const.ComboColumnAttributes.ALL_MALWARE],
                                        record[const.ComboColumnAttributes.ALL_BENIGN],
                                        this_hit_ratio_to_hit_more, this_hit_ratio_to_hit_less,
                                        this_hit_cnt_to_hit_more, this_hit_cnt_to_hit_less, time_elapsed]

            ordered_combos = np.array(list(self.sorting_heuristic_score.keys()))
            ordered_scores = []
            for combo in ordered_combos:
                ordered_scores.append(self.sorting_heuristic_score[combo])

            sorted_idx = np.argsort(ordered_scores)[::-1]
            sorted_combos = np.array(ordered_combos)[sorted_idx]
            for combo in sorted_combos:
                fh_out.write(f'{",".join(combo_records[combo])},{self.sorting_heuristic_score[combo]}\n')
        return summary_to_return

    def calculate_heuristic_score(self, combo, this_hit_ratio_to_hit_more, this_hit_ratio_to_hit_less,
                                  this_hit_cnt_to_hit_more, this_hit_cnt_to_hit_less):
        self.sorting_heuristic_score[combo] = -1

        this_hit_ratio_to_hit_more = float(this_hit_ratio_to_hit_more)
        this_hit_ratio_to_hit_less = float(this_hit_ratio_to_hit_less)
        this_hit_cnt_to_hit_more = int(this_hit_cnt_to_hit_more)
        this_hit_cnt_to_hit_less = int(this_hit_cnt_to_hit_less)

        sorting_criteria = CommonConfig.get_combo_sorting_criteria()
        if this_hit_cnt_to_hit_more == 0:
            self.sorting_heuristic_score[combo] = 0
        elif this_hit_cnt_to_hit_less == 0:
            self.sorting_heuristic_score[combo] = 1000000
        else:
            if sorting_criteria == 'mfibf' or sorting_criteria == 'mfibf1':
                heuristic_score = this_hit_ratio_to_hit_more / this_hit_ratio_to_hit_less
            elif sorting_criteria == 'mfibf2':
                self.sorting_heuristic_score[combo] = this_hit_ratio_to_hit_more ** 2 / this_hit_ratio_to_hit_less
            elif sorting_criteria == 'f05':
                tp, fp = this_hit_cnt_to_hit_more, this_hit_cnt_to_hit_less
                fn = int(this_hit_cnt_to_hit_more*100/this_hit_ratio_to_hit_more) - tp   # total #malware - tp
                heuristic_score = (1 + 0.5 * 0.5) * tp / ((1 + 0.5 * 0.5) * tp + 0.5 * 0.5 * fn + fp)
            else:
                print('Unknown property sorting heuristic.')
                heuristic_score = -1
            self.sorting_heuristic_score[combo] = heuristic_score
