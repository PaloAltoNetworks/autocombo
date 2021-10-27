"""
@author: Min Du (midu@paloaltonetworks.com)
Copyright (c) 2021 Palo Alto Networks
"""

import time
import logging

from utils import misc
from utils import const
from worker import combo_property_sorter


if __name__ == '__main__':
    misc.init_logger(const.get_data_preparation_logs_filename())
    logger = logging.getLogger(misc.get_logger_name(__name__))
    logger.info('Property sorter start.')
    start_time = time.time()
    try:
        sorter = combo_property_sorter.PropertySorter()
        sorter.sort_properties()
    except Exception:
        info = 'Exception in property sorter.'
        logger.exception(info)
    time_elapsed = time.time() - start_time
    end_msg = f'Property sorter end. Time elapsed {time_elapsed:.2f} seconds'
    logger.info(end_msg)
