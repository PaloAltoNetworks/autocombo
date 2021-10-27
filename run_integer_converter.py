"""
@author: Min Du (midu@paloaltonetworks.com)
Copyright (c) 2021 Palo Alto Networks
"""

import time
import logging

from utils import misc
from utils import const
from worker import property_lists_integer_converter


if __name__ == '__main__':
    misc.init_logger(const.get_data_preparation_logs_filename())
    logger = logging.getLogger(misc.get_logger_name(__name__))
    logger.info('Property integer converter start.')
    start_time = time.time()
    try:
        convertor = property_lists_integer_converter.IntegerConverter()
        convertor.convert_properties2integers()
    except Exception:
        info = 'Exception in property integer converter.'
        logger.exception(info)
    time_elapsed = time.time() - start_time
    end_msg = f'Property integer converter end. Time elapsed {time_elapsed:.2f} seconds'
    logger.info(end_msg)
