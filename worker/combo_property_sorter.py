"""
@author: Min Du (midu@paloaltonetworks.com)
Copyright (c) 2021 Palo Alto Networks
"""

import os
import csv
import json
import logging

from utils import misc
from utils import const
from utils.config_parser import CommonConfig


class PropertySorter:
    """
    Property Sorter
    """

    def __init__(self):
        self.logger = logging.getLogger(misc.get_logger_name(__name__))
        self.logger.info('Current logging level: %s', self.logger.getEffectiveLevel())

        self.property_cnt_to_hit_more = {}  # DA : {bhr: cnt}
        self.property_cnt_to_hit_less = {}  # DA : {bhr: cnt}
        self.total_cnt_to_hit_more = 0
        self.total_cnt_to_hit_less = 0
        self.all_properties = set()

    def sort_properties(self):
        summary_to_return = ['Summary: ']
        self.logger.info(f'Sorting property lists from folder {const.get_property_lists_raw_folder()}')

        # load in all data
        self.property_cnt_to_hit_less, self.total_cnt_to_hit_less = self.load_properties(gt_labels=[0])
        self.property_cnt_to_hit_more, self.total_cnt_to_hit_more = self.load_properties(gt_labels=[1])

        property_heuristic_score = {}
        for bhr in self.all_properties:
            self.logger.debug(f'get score for property {bhr}')
            score, ratio_more, ratio_less = self.get_heuristic_score(bhr)
            if score >= 0:
                property_heuristic_score[f'{bhr}'] = {'score': score, 'ratio-more': ratio_more,
                                                      'ratio-less': ratio_less}
            # except Exception:
            #     self.logger.info(f'Skip property {bhr} because it is a yara type')
            #     continue
        sorted_heuristic_score = {k: v for k, v in sorted(property_heuristic_score.items(),
                                                          key=lambda item: item[1]['score'], reverse=True)}
        with open(const.get_all_sorted_property_file(), 'w') as fh:
            csv_writer = csv.writer(fh)
            header = ['property', 'heuristic-score', 'malicious-ratio', 'benign-ratio']
            csv_writer.writerow(header)
            for k, v in sorted_heuristic_score.items():
                csv_writer.writerow([k, v['score'], v['ratio-more'], v['ratio-less']])

        summary_to_return.append(f'Sorted properties are stored in {const.get_all_sorted_property_file()}.')

        return summary_to_return

    def load_properties(self, gt_labels):
        property_cnt = {}
        total_cnt = 0
        start_date, end_date = misc.get_start_end_date_for_combo_generation()
        property_lists_raw_folder = const.get_property_lists_raw_folder()

        for date in misc.date_range(start_date, end_date):
            for gt_label in gt_labels:
                property_base_file = const.get_base_property_file_name(date, gt_label)
                property_lists_file = os.path.join(property_lists_raw_folder, property_base_file)
                if not os.path.exists(property_lists_file):
                    self.logger.error('File %s not exist, skip.', property_lists_file)
                    continue
                with open(property_lists_file) as fh_in:
                    self.logger.info('Getting property counts from file %s', property_lists_file)
                    sha256_properties = json.load(fh_in)
                    for sha256, properties in sha256_properties.items():
                        total_cnt += 1
                        for bhr in properties:
                            self.all_properties.add(bhr)
                            if bhr in property_cnt:
                                property_cnt[bhr] += 1
                            else:
                                property_cnt[bhr] = 1
        return property_cnt, total_cnt

    def get_heuristic_score(self, bhr):
        sorting_criteria = CommonConfig.get_property_sorting_criteria()
        heuristic_score, ratio_to_hit_more, ratio_to_hit_less = -1, -1, -1
        property_cnt_to_hit_more = self.property_cnt_to_hit_more
        property_cnt_to_hit_less = self.property_cnt_to_hit_less
        total_cnt_to_hit_more = self.total_cnt_to_hit_more
        total_cnt_to_hit_less = self.total_cnt_to_hit_less

        if bhr in property_cnt_to_hit_more and bhr in property_cnt_to_hit_less:
            ratio_to_hit_more = property_cnt_to_hit_more[bhr]/total_cnt_to_hit_more
            ratio_to_hit_less = property_cnt_to_hit_less[bhr]/total_cnt_to_hit_less

            if sorting_criteria == 'mfibf' or sorting_criteria == 'mfibf1':
                heuristic_score = ratio_to_hit_more / ratio_to_hit_less
            elif sorting_criteria == 'mfibf2':
                heuristic_score = ratio_to_hit_more ** 2 / ratio_to_hit_less
            elif sorting_criteria == 'f05':
                tp, fp = property_cnt_to_hit_more[bhr], property_cnt_to_hit_less[bhr]
                fn = total_cnt_to_hit_more - tp
                heuristic_score = (1 + 0.5 * 0.5) * tp / ((1 + 0.5 * 0.5) * tp + 0.5 * 0.5 * fn + fp + 1e-07)
            else:
                print('Unknown property sorting heuristic.')
                heuristic_score = -1
        elif bhr in property_cnt_to_hit_more and bhr not in property_cnt_to_hit_less:
            ratio_to_hit_more = property_cnt_to_hit_more[bhr] / total_cnt_to_hit_more
            ratio_to_hit_less = 0
            heuristic_score = 1000000 * ratio_to_hit_more
        elif bhr not in property_cnt_to_hit_more and bhr in property_cnt_to_hit_less:
            ratio_to_hit_more = 0
            ratio_to_hit_less = property_cnt_to_hit_less[bhr] / total_cnt_to_hit_less
            heuristic_score = 1e-07/ratio_to_hit_less
        return heuristic_score, ratio_to_hit_more, ratio_to_hit_less
