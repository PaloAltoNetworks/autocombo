"""
@author: Min Du (midu@paloaltonetworks.com)
Copyright (c) 2021 Palo Alto Networks
"""

import os
import json
import logging

from datetime import date, datetime, timedelta
from logging.config import fileConfig

from utils import const
from utils.config_parser import CommonConfig


def date_range(start_date, end_date):
    for n in range(int((end_date - start_date).days)+1):
        yield start_date + timedelta(n)


def get_start_end_date_for_dataset_preparation():
    start_date = datetime.strptime(CommonConfig.get_start_date('dataset_preparer'), '%Y-%m-%d')
    end_date = datetime.strptime(CommonConfig.get_end_date('dataset_preparer'), '%Y-%m-%d')
    return start_date, end_date


def get_start_end_date_for_combo_generation():
    start_date = datetime.strptime(CommonConfig.get_start_date('combo_generation'), '%Y-%m-%d')
    end_date = datetime.strptime(CommonConfig.get_end_date('combo_generation'), '%Y-%m-%d')
    return start_date, end_date


def get_start_end_date_for_combo_evaluation():
    start_date = datetime.strptime(CommonConfig.get_start_date('combo_evaluation'), '%Y-%m-%d')
    end_date = datetime.strptime(CommonConfig.get_end_date('combo_evaluation'), '%Y-%m-%d')
    return start_date, end_date


def get_logger_name(module_name, class_name=None):
    if class_name is not None:
        return f'{const.PROJECT_NAME}.{module_name}.{class_name}'
    else:
        return f'{const.PROJECT_NAME}.{module_name}'


def init_logger(log_file):
    print('log_config', const.get_log_config_file())
    config = {'debug_logfile': log_file}
    fileConfig(const.get_log_config_file(), config)


def pretty_json_format(in_val):
    return json.dumps(in_val, sort_keys=True, indent=4, separators=(',', ': '))

def load_property_integers(gt_labels, start_date, end_date):
    total_sha256_integers = {}
    property_lists_integer_folder = const.get_property_lists_integer_folder()

    for date in date_range(start_date, end_date):
        for gt_label in gt_labels:
            property_base_file = const.get_base_property_file_name(date, gt_label)
            integer_file = os.path.join(property_lists_integer_folder, property_base_file)
            if not os.path.exists(integer_file):
                logging.error('File %s not exist, skip.', integer_file)
                continue
            with open(integer_file) as fh:
                this_sha256_integers = json.load(fh)
                for sha256, integers in this_sha256_integers.items():
                    total_sha256_integers[sha256] = integers
                logging.info(f'Loaded integer file {integer_file}, #hashes: {len(this_sha256_integers)}')
    logging.info(f'Total #hashes to return for gt_labels {gt_labels}: '
                 f'{len(total_sha256_integers)}')
    return total_sha256_integers


def load_property_sets(gt_labels, start_date, end_date):
    total_sha256_properties = {}
    property_lists_folder = const.get_property_lists_raw_folder()

    for date in date_range(start_date, end_date):
        for gt_label in gt_labels:
            property_base_file = const.get_base_property_file_name(date, gt_label)
            property_file = os.path.join(property_lists_folder, property_base_file)
            if not os.path.exists(property_file):
                logging.error('File %s not exist, skip.', property_file)
                continue
            with open(property_file) as fh:
                this_sha256_properties = json.load(fh)
                for sha256, properties in this_sha256_properties.items():
                    total_sha256_properties[sha256] = set([str(bhr) for bhr in properties])
                logging.info(f'Loaded property file {property_file}, #hashes: {len(this_sha256_properties)}')
    logging.info(f'Total #hashes to return for gt_labels {gt_labels}: '
                 f'{len(total_sha256_properties)}')
    # print(f'total_sha256_properties: {total_sha256_properties.keys()}')
    return total_sha256_properties


def get_hash_properties_stats_info(hash_property_file):
    if os.path.exists(hash_property_file):
        with open(hash_property_file) as fh:
            contents = json.load(fh)
            stats = {}
            for hash, properties in contents.items():
                for prop in properties:
                    if prop in stats:
                        stats[prop] += 1
                    else:
                        stats[prop] = 1
        return f'(num_hashes: {len(contents)}), {stats}'
    else:
        return f'File not exist'


def get_property_index_mapping():
    with open(const.get_property_index_mapping_file()) as fh:
        property_index_mapping = json.load(fh)
    return property_index_mapping
