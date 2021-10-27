"""
@author: Min Du (midu@paloaltonetworks.com)
Copyright (c) 2021 Palo Alto Networks
"""

import os
import json
import logging

from utils import const
from utils import misc

misc.init_logger(const.get_data_preparation_logs_filename())
logger = logging.getLogger(misc.get_logger_name(__name__))

property_set = set()

start_date, end_date = misc.get_start_end_date_for_dataset_preparation()

for date in misc.date_range(start_date, end_date):
    for gt_label in [0, 1]:
        property_file = os.path.join(const.get_property_lists_raw_folder(),
                                     const.get_base_property_file_name(date, gt_label))
        if not os.path.exists(property_file):
            logger.error(f'File {property_file} does not exist, continue.')
            continue
        logger.info(f'Loading property file {property_file}')
        with open(property_file) as fh_in:
            sha256_properties = json.load(fh_in)
            for sha256, properties in sha256_properties.items():
                property_set.update(properties)

logger.info(f'Loading complete. #properties: {len(property_set)}')


all_property_sorted_list = sorted(list(property_set), key=lambda x: int(x))
property_index_mapping_file = const.get_property_index_mapping_file()
index_mapping = {}
if os.path.exists(property_index_mapping_file):
    with open(property_index_mapping_file) as fh:
        index_mapping = json.load(fh)
max_id = len(index_mapping)
for key in all_property_sorted_list:
    if str(key) not in index_mapping:
        index_mapping[str(key)] = max_id
        max_id += 1
with open(property_index_mapping_file, 'w') as fh:
    json.dump(index_mapping, fh)
