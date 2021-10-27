"""
@author: Min Du (midu@paloaltonetworks.com)
Copyright (c) 2021 Palo Alto Networks
"""

import os
import sys
import ast

from configparser import ConfigParser


class CommonConfig:
    CONFIG_PARSER = ConfigParser()
    common_config = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'config', 'common_config.ini'))
    CONFIG_PARSER.read([common_config])

    @staticmethod
    def get_data_folder():
        folder = os.path.abspath(os.path.join(os.path.dirname(__file__), '..',
                                              CommonConfig.CONFIG_PARSER.get('common', 'data_folder')))
        os.makedirs(folder, exist_ok=True)
        return folder

    @staticmethod
    def get_data_preparation_logs_folder():
        folder = os.path.abspath(os.path.join(os.path.dirname(__file__), '..',
                                              CommonConfig.CONFIG_PARSER.get('common', 'data_preparation_logs_folder')))
        os.makedirs(folder, exist_ok=True)
        return folder

    @staticmethod
    def get_model_preparation_logs_folder():
        folder = os.path.abspath(os.path.join(os.path.dirname(__file__), '..',
                                              CommonConfig.CONFIG_PARSER.get('common', 'model_preparation_logs_folder')))
        os.makedirs(folder, exist_ok=True)
        return folder

    @staticmethod
    def get_property_lists_folder():
        folder = CommonConfig.CONFIG_PARSER.get('dataset_preparer', 'property_lists_folder')
        os.makedirs(folder, exist_ok=True)
        return folder

    @staticmethod
    def get_property_lists_integer_folder():
        folder = CommonConfig.CONFIG_PARSER.get('dataset_preparer', 'property_lists_integer_folder')
        os.makedirs(folder, exist_ok=True)
        return folder

    @staticmethod
    def get_property_index_mapping_file():
        return CommonConfig.CONFIG_PARSER.get('dataset_preparer', 'property_index_mapping_file')

    @staticmethod
    def get_property_count():
        return CommonConfig.CONFIG_PARSER.getint('dataset_preparer', 'property_count')

    @staticmethod
    def get_combo_generation_result_folder():
        folder = CommonConfig.CONFIG_PARSER.get('combo_generation', 'result_folder')
        os.makedirs(folder, exist_ok=True)
        return folder

    @staticmethod
    def get_start_date(config_section):
        return CommonConfig.CONFIG_PARSER.get(config_section, 'start_date')

    @staticmethod
    def get_end_date(config_section):
        return CommonConfig.CONFIG_PARSER.get(config_section, 'end_date')

    @staticmethod
    def get_property_sorting_criteria():
        return CommonConfig.CONFIG_PARSER.get('combo_generation', 'property_sorting_criteria')

    @staticmethod
    def get_min_threshold():
        return CommonConfig.CONFIG_PARSER.getfloat('combo_generation', 'min_threshold')

    @staticmethod
    def get_max_threshold():
        return CommonConfig.CONFIG_PARSER.getfloat('combo_generation', 'max_threshold')

    @staticmethod
    def get_min_combo_size():
        return CommonConfig.CONFIG_PARSER.getint('combo_generation', 'min_combo_size')

    @staticmethod
    def get_max_combo_size():
        return CommonConfig.CONFIG_PARSER.getint('combo_generation', 'max_combo_size')

    @staticmethod
    def get_combo_sorting_criteria():
        return CommonConfig.CONFIG_PARSER.get('combo_selection', 'combo_sorting_criteria')

    @staticmethod
    def get_combo_selection_approach():
        return CommonConfig.CONFIG_PARSER.get('combo_selection', 'combo_selection_approach')

    @staticmethod
    def get_generation_mode():
        return CommonConfig.CONFIG_PARSER.get('combo_generation', 'generation_mode')

    @staticmethod
    def get_use_integer_subset():
        return CommonConfig.CONFIG_PARSER.getboolean('combo_generation', 'use_integer_subset')

    @staticmethod
    def get_do_property_sorting():
        return CommonConfig.CONFIG_PARSER.getboolean('combo_generation', 'do_property_sorting')

    @staticmethod
    def get_random_seed():
        return CommonConfig.CONFIG_PARSER.getint('combo_generation', 'random_seed')

    @staticmethod
    def get_use_multi_threading():
        return CommonConfig.CONFIG_PARSER.getboolean('combo_generation', 'use_multi_threading')

    @staticmethod
    def get_num_cores():
        return CommonConfig.CONFIG_PARSER.getint('combo_generation', 'num_cores')

    @staticmethod
    def get_use_sorted_combo_file_for_eval():
        return CommonConfig.CONFIG_PARSER.getboolean('combo_evaluation', 'sorted_combo_file')

    @staticmethod
    def get_use_selected_combo_file():
        return CommonConfig.CONFIG_PARSER.getboolean('combo_evaluation', 'use_selected_combo_file')

    @staticmethod
    def get_selection_threshold():
        return CommonConfig.CONFIG_PARSER.getfloat('combo_selection', 'selection_threshold')
