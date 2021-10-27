"""
@author: Min Du (midu@paloaltonetworks.com)
Copyright (c) 2021 Palo Alto Networks
"""

import os
import csv
import logging

from utils import misc
from utils import const
from utils.config_parser import CommonConfig


class ComboEvaluator:

    def __init__(self):
        self.logger = logging.getLogger(misc.get_logger_name(__name__))
        self.logger.info('Current logging level: %s', self.logger.getEffectiveLevel())
        pil_logger = logging.getLogger('PIL')
        pil_logger.setLevel(logging.INFO)

        self.property_index_mapping = {}  # {bhr : id}

        self.malware_hits_sofar = set()
        self.benign_hits_sofar = set()

    def evaluate_combos(self):
        summary_to_return = ['Summary: ']
        if CommonConfig.get_use_selected_combo_file():
            input_combo_file = const.get_selected_combo_file(const.get_generated_combo_file())
            # # evaluated_combo_file = const.get_selected_combo_evaluation_file()
            # evaluated_combo_file = const.get_combo_evaluation_file(input_combo_file)
            # hit_hashes_folder = const.get_eval_combo_evaluation_hit_hashes_folder()
        elif CommonConfig.get_use_sorted_combo_file_for_eval():
            input_combo_file = const.get_sorted_combo_file(const.get_generated_combo_file())
            # evaluated_combo_file = const.get_combo_evaluation_file(input_combo_file)
            # # evaluated_combo_file = const.get_sorted_combo_evaluation_file()
            # hit_hashes_folder = const.get_eval_combo_evaluation_hit_hashes_folder()
        else:
            input_combo_file = const.get_generated_combo_file()
        evaluated_combo_file = const.get_combo_evaluation_file(input_combo_file)
        hit_hashes_folder = const.get_eval_combo_evaluation_hit_hashes_folder(input_combo_file)

        self.logger.info(f'Starting to evaluate combo file {input_combo_file}')
        summary_to_return.append(f'Evaluated combo file {evaluated_combo_file}')


        start_date, end_date = misc.get_start_end_date_for_combo_evaluation()

        self.malware_sets = misc.load_property_sets(gt_labels=[1],
                                                    start_date=start_date, end_date=end_date)
        self.benign_sets = misc.load_property_sets(gt_labels=[0],
                                                   start_date=start_date, end_date=end_date)
        self.logger.info(f'Loaded sets to eval: #malware: {len(self.malware_sets)}, #benign: {len(self.benign_sets)}')
        # for sha256, bhr_set in self.malware_sets.items():
        #     print(f'debugging, {sha256}, {bhr_set}')
        self.property_index_mapping = misc.get_property_index_mapping()

        with open(input_combo_file) as fh_in, open(evaluated_combo_file, 'w') as fh_out:
            csv_writer = csv.writer(fh_out, delimiter=',')
            all_lns = fh_in.readlines()
            header = [f'gen-{x}' for x in all_lns[0].strip().split(',')]
            header += ['tp', 'fp', 'tpr', 'fpr', 'TP-sofar', 'FP-sofar',  'TPR-sofar', 'FPR-sofar', 'eval-malware', 'eval-benign']
            csv_writer.writerow(header)
            for ln in all_lns[1:]:
                one_record = ln.strip().split(',')
                combo = one_record[0]
                self.logger.info('Evaluating combo %s', combo)
                tp_file, fp_file = os.path.join(hit_hashes_folder, f'{combo}.tp'), os.path.join(hit_hashes_folder, f'{combo}.fp')
                malware_hits, benign_hits = set(), set()
                # if os.path.exists(tp_file):
                #     with open(tp_file) as fhtp:
                #         for lntp in fhtp.readlines():
                #             malware_hits.add(lntp.strip())
                # else:
                # malware_hits = self.get_hit_count(combo, self.malware_integers)
                malware_hits = self.get_hit_hashes(combo, self.malware_sets)
                with open(tp_file, 'w') as fh_tp:
                    for sha256 in malware_hits:
                        fh_tp.write(f'{sha256}\n')
                if os.path.exists(fp_file):
                    with open(fp_file) as fhtp:
                        for lntp in fhtp.readlines():
                            benign_hits.add(lntp.strip())
                else:
                    # benign_hits = self.get_hit_count(combo, self.benign_integers)
                    benign_hits = self.get_hit_hashes(combo, self.benign_sets)
                    with open(fp_file, 'w') as fh_fp:
                        for sha256 in benign_hits:
                            fh_fp.write(f'{sha256}\n')
                self.malware_hits_sofar.update(malware_hits)
                self.benign_hits_sofar.update(benign_hits)
                one_record += [len(malware_hits), len(benign_hits),
                               len(malware_hits)*100.0/len(self.malware_sets),
                               len(benign_hits)*100.0/len(self.benign_sets),
                               len(self.malware_hits_sofar), len(self.benign_hits_sofar),
                               len(self.malware_hits_sofar)*100.0/len(self.malware_sets),
                               len(self.benign_hits_sofar)*100.0/len(self.benign_sets),
                               len(self.malware_sets), len(self.benign_sets)]
                csv_writer.writerow(one_record)
                fh_out.flush()

        return summary_to_return

    def get_hit_hashes(self, candidate, sha256_properties):
        candidate = set(candidate.strip().split('-'))
        hit_hashes = set()
        # self.logger.debug(f'len(sha256_properties): {len(sha256_properties)}')
        for sha256, bhrs in sha256_properties.items():
            # self.logger.debug(f'candidate: {candidate}, bhrs: {bhrs}')
            if candidate.issubset(bhrs):
                hit_hashes.add(sha256)
        return hit_hashes

    # def get_hit_count_by_properties(self, property_set_to_check, property_hashes, hit_hashes_already):
    #     hit_hashes = self.get_hit_hashes(property_set_to_check, property_hashes)
    #     hit_hashes_already.update(hit_hashes)
    #     return hit_hashes

    def get_hit_count(self, combo, hash_integers):
        full_int = self._get_integer(combo)
        hit_hashes = set()
        for sha256, integer in hash_integers.items():
            if self.first_in_second(full_int, integer):
                hit_hashes.add(sha256)
        return hit_hashes

    def _get_integer(self, combo):
        properties = combo.split('-')
        ret = 0
        for b in properties:
            if b not in self.property_index_mapping:
                return -1
            ret |= 1 << self.property_index_mapping[b]
        return ret

    def first_in_second(self, first_int, second_int):
        return first_int & second_int == first_int
