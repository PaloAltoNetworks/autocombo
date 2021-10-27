"""
@author: Min Du (midu@paloaltonetworks.com)
Copyright (c) 2021 Palo Alto Networks
"""


import sys
import time
import logging

from utils import misc
from utils import const
from utils.config_parser import CommonConfig


mode = CommonConfig.get_generation_mode()
if mode == 'prestore':
    from worker import combo_generator_store_hashes_per_property_first as combo_generator
else:
    from worker import combo_generator

if __name__ == '__main__':
    print(f'Generation mode: {mode}')
    misc.init_logger(const.get_data_preparation_logs_filename())
    logger = logging.getLogger(misc.get_logger_name(__name__))
    logger.info('Combo generator start.')
    start_time = time.time()
    try:
        generator = combo_generator.ComboGenerator()
        generator.generate_combos()
    except Exception:
        info = 'Exception in combo generator.'
        logger.exception(info)
    time_elapsed = time.time() - start_time
    end_msg = f'Combo generator end. Time elapsed {time_elapsed:.2f} seconds'
    logger.info(end_msg)
