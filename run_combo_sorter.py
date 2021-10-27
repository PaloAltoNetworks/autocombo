"""
@author: Min Du (midu@paloaltonetworks.com)
Copyright (c) 2021 Palo Alto Networks
"""

import time
import logging

from utils import misc
from utils import const
from worker import combo_sorter


if __name__ == '__main__':
    misc.init_logger(const.get_data_preparation_logs_filename())
    logger = logging.getLogger(misc.get_logger_name(__name__))
    logger.info('Combo sorter start.')
    start_time = time.time()
    try:
        sorter = combo_sorter.ComboSorter()
        sorter.sort_combos()
    except Exception:
        info = 'Exception in combo sorter.'
        logger.exception(info)
    time_elapsed = time.time() - start_time
    end_msg = f'Combo sorter end. Time elapsed {time_elapsed:.2f} seconds'
    logger.info(end_msg)
