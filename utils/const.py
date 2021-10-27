"""
@author: Min Du (midu@paloaltonetworks.com)
Copyright (c) 2021 Palo Alto Networks
"""

import os

from utils import misc
from utils.config_parser import CommonConfig


PROJECT_NAME = 'autocombo_pipeline'


class ComboColumnAttributes:
    COMBO = 0
    ALL_MALWARE = 1
    ALL_BENIGN = 2
    THIS_HIT_RATIO_TO_HIT_MORE = 3
    THIS_HIT_RATIO_TO_HIT_LESS = 4
    THIS_HIT_CNT_TO_HIT_MORE = 5
    THIS_HIT_CNT_TO_HIT_LESS = 6
    TIME_ELAPSED = 11


def load_property_id_type_mapping():
    property_id_type_mapping = {}
    property_id_file = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'bin', 'property_id_type.csv'))
    with open(property_id_file) as fh:
        for ln in fh.readlines()[1:]:
            tmp = ln.strip().split()
            if len(tmp) > 2:
                property_id_type_mapping[str(tmp[0])] = tmp[1]
    return property_id_type_mapping


def load_previously_generated_combos():
    previous_combos = []
    previous_combo_folder = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                         '..', 'bin', 'previously_generated_combos'))
    for combo_file in os.listdir(previous_combo_folder):
        with open(os.path.join(previous_combo_folder, combo_file)) as fh:
            for ln in fh.readlines()[1:]:
                combo_set = set(ln.strip().split(',')[1].split(';'))
                previous_combos.append(combo_set)

    return previous_combos


def get_data_preparation_logs_filename():
    log_dir = CommonConfig.get_data_preparation_logs_folder()
    return os.path.join(log_dir, f'data_preparation.log')


def get_log_config_file():
    return os.path.join('config', 'log_config.ini')


def get_base_property_file_name(date, gt_label):
    """
    Generate sha256 file name to store all samples in BMS2.0 having input date, gt_label
    """
    return f'sample_property_lists_anonymized_{date.strftime("%Y-%m-%d")}_gt{gt_label}'


def get_property_lists_raw_folder():
    folder = os.path.join(CommonConfig.get_data_folder(), CommonConfig.get_property_lists_folder())
    os.makedirs(folder, exist_ok=True)
    return folder


def get_property_lists_integer_folder():
    folder = os.path.join(CommonConfig.get_data_folder(),
                          CommonConfig.get_property_lists_integer_folder())
    os.makedirs(folder, exist_ok=True)
    return folder


def get_property_index_mapping_file():
    return os.path.join(CommonConfig.get_data_folder(),
                        CommonConfig.get_property_index_mapping_file())


def get_combo_generation_result_folder():
    start_date, end_date = misc.get_start_end_date_for_combo_generation()

    sub_folder_name = f'start-{start_date.strftime("%Y-%m-%d")}.' \
                      f'end-{end_date.strftime("%Y-%m-%d")}.' \
                      f'propertySorting-{CommonConfig.get_property_sorting_criteria()}'
    folder = os.path.join(CommonConfig.get_data_folder(),
                          CommonConfig.get_combo_generation_result_folder(), sub_folder_name)
    os.makedirs(folder, exist_ok=True)
    return folder


def get_combo_generation_result_folder_pe():
    start_date, end_date = misc.get_start_end_date_for_combo_generation()

    sub_folder_name = f'start-{start_date.strftime("%Y-%m-%d")}.' \
                      f'end-{end_date.strftime("%Y-%m-%d")}.' \
                      f'propertySorting-{CommonConfig.get_property_sorting_criteria()}'
    folder = os.path.join(CommonConfig.get_data_folder(), 'pe',
                          CommonConfig.get_combo_generation_result_folder(), sub_folder_name)
    os.makedirs(folder, exist_ok=True)
    return folder


def get_all_sorted_property_file():
    return os.path.join(get_combo_generation_result_folder(), 'sorted-properties.csv')


def get_not_sorted_property_file():
    return os.path.join(get_combo_generation_result_folder(),
                        f'not-sorted-properties-seed{CommonConfig.get_random_seed()}.csv')


def get_min_threshold():
    min_threshold = CommonConfig.get_min_threshold()
    return min_threshold


def get_max_threshold():
    max_threshold = CommonConfig.get_max_threshold()
    return max_threshold


def get_generated_combo_folder():
    use_integer_subset = CommonConfig.get_use_integer_subset()
    do_property_sorting = CommonConfig.get_do_property_sorting()
    generation_mode = CommonConfig.get_generation_mode()

    folder = os.path.join(get_combo_generation_result_folder(), f'minThres-{get_min_threshold()}.'
                                                                f'maxThres-{get_max_threshold()}.'
                                                                f'minComboSize-{CommonConfig.get_min_combo_size()}.'
                                                                f'maxComboSize-{CommonConfig.get_max_combo_size()}.'
                                                                f'generationMode-{generation_mode}')
    if generation_mode == 'ablation_study':
        folder = f'{folder}.' \
                 f'useIntegerSubset-{use_integer_subset}.' \
                 f'doPropertySorting-{do_property_sorting}.' \
                 f'seed{CommonConfig.get_random_seed()}'
    elif generation_mode == 'multi_processing':
        folder = f'{folder}.numCores-{CommonConfig.get_num_cores()}'

    os.makedirs(folder, exist_ok=True)
    return folder


def get_generated_combo_file():
    return os.path.join(get_generated_combo_folder(), f'generated-combos.csv')


def get_generated_combo_hit_hashes_folder():
    folder = os.path.join(get_generated_combo_folder(), f'generated-combos-hit-hashes')
    os.makedirs(folder, exist_ok=True)
    return folder


def get_gen_combo_evaluation_hit_hashes_folder():
    start_date, end_date = misc.get_start_end_date_for_combo_generation()
    folder = get_generated_combo_folder()
    folder = os.path.join(folder, f'generated-combos.'
                                  f'eval-start-{start_date.strftime("%Y-%m-%d")}.'
                                  f'end-{end_date.strftime("%Y-%m-%d")}.hit_hashes')
    os.makedirs(folder, exist_ok=True)
    return folder


def get_sorted_combo_file(combo_file_to_sort):
    return f'{combo_file_to_sort}.sorted-{CommonConfig.get_combo_sorting_criteria()}.csv'


def get_combo_evaluation_file(combo_file_to_eval):
    start_date, end_date = misc.get_start_end_date_for_combo_evaluation()
    return f'{combo_file_to_eval}.eval-start-{start_date.strftime("%Y-%m-%d")}.' \
           f'end-{end_date.strftime("%Y-%m-%d")}.csv'


def get_eval_combo_evaluation_hit_hashes_folder(combo_file_to_eval):
    start_date, end_date = misc.get_start_end_date_for_combo_evaluation()
    folder = f'{combo_file_to_eval}.eval-start-{start_date.strftime("%Y-%m-%d")}.' \
             f'end-{end_date.strftime("%Y-%m-%d")}.hit_hashes'
    os.makedirs(folder, exist_ok=True)
    return folder


def get_selected_combo_file(combo_file_to_select):
    selection_criteria = CommonConfig.get_combo_selection_approach()
    return f'{combo_file_to_select}.{selection_criteria}.rank-{CommonConfig.get_combo_sorting_criteria()}.' \
           f'selected-{CommonConfig.get_selection_threshold()}.csv'


def get_eval_start_end_str():
    start_date, end_date = misc.get_start_end_date_for_combo_evaluation()
    return f'start-{start_date.strftime("%Y%m%d")}.end-{end_date.strftime("%Y%m%d")}'

def get_start_end_str(start_date, end_date):
    return f'start-{start_date.strftime("%Y%m%d")}.end-{end_date.strftime("%Y%m%d")}'

