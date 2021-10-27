"""
@author: Min Du (midu@paloaltonetworks.com)
Copyright (c) 2021 Palo Alto Networks
"""

import os
import json
import logging

from utils import misc
from utils import const
from utils.config_parser import CommonConfig


class IntegerConverter:
    """
    Integer Converter
    """

    def __init__(self):
        self.logger = logging.getLogger(misc.get_logger_name(__name__))
        self.logger.info('Current logging level: %s', self.logger.getEffectiveLevel())

        self.property_index_mapping = {}

    def convert_properties2integers(self):
        """
        Purpose: convert each property list into an integer
        """
        summary_to_return = ['Summary: ']
        property_lists_raw_folder = const.get_property_lists_raw_folder()
        property_lists_integer_folder = const.get_property_lists_integer_folder()
        start_date, end_date = misc.get_start_end_date_for_dataset_preparation()
        summary_to_return.append(f'Property list integers are stored into folder {property_lists_integer_folder}')

        self.property_index_mapping = misc.get_property_index_mapping()
        for date in misc.date_range(start_date, end_date):
            for gt_label in [0, 1]:
                property_base_file = const.get_base_property_file_name(date, gt_label)
                property_lists_file = os.path.join(property_lists_raw_folder, property_base_file)
                integer_file = os.path.join(property_lists_integer_folder, property_base_file)
                self.logger.info('Converting property file %s', property_lists_file)
                if not os.path.exists(property_lists_file):
                    self.logger.error('File %s not exists, continue.', property_lists_file)
                    continue
                with open(property_lists_file) as fh_in, open(integer_file, 'w') as fh_out:
                    sha256_properties = json.load(fh_in)
                    sha256_integers = {}
                    for sha256, properties in sha256_properties.items():
                        sha256_integers[sha256] = self.get_integer(properties)
                    fh_out.write(misc.pretty_json_format(sha256_integers))
                self.logger.info(f'Generated property integer file. {property_base_file}')
        return summary_to_return

    def get_integer(self, properties):
        ret = 0
        for b in properties:
            ret |= 1 << self.property_index_mapping[str(b)]
        return ret

