## Introduction
This repository contains the demo code and dataset used in our paper [AutoCombo](https://dl.acm.org/doi/abs/10.1145/3459637.3481896). 

To use the code and/or dataset, please kindly cite our paper:

_Min Du, Wenjun Hu, and William Hewlett. "AutoCombo: Automatic Malware Signature Generation Through Combination Rule Mining." In Proceedings of the 30th ACM International Conference on Information & Knowledge Management, pp. 3777-3786. 2021._


## Prerequisites
Python 3

## Dataset
*./dataset/property_lists_raw* folder contains a couple of example files. 

**To get the complete dataset, please email data-sets@paloaltonetworks.com**


## Dataset Preparation
*Input: property lists within time range*
```
[dataset_preparer]
start_date = 2020-07-01
end_date = 2020-07-31

```
- Step 1: generate property-index mapping
```
python generate_property_index_mapping.py

Output: ./dataset/property_index_mapping.json
```


- Step 2: convert property lists into integers
```
python run_integer_converter.py
Output: ./dataset/property_lists_integer
```


## Signature Generation
*Input: property lists within time range*
```
[combo_generation]
start_date = 2020-07-01
end_date = 2020-07-15
```
*Output: all intermediate results in this step are stored into folder ./dataset/combo_generation_results*

### Signature creation
*choose different generation mode in config file ./config/common_config.ini*:
```
[combo_generation]
; choose from:
; ablation_study
; multi_processing
; store_parent_hits
; prestore (hashes-per-property)
generation_mode = prestore
; for ablation study
use_integer_subset = True
do_property_sorting = True
; for multi_processing
num_cores = 20
```

- Step 1: sort properties with MF-IBF or other heuristic
```
python run_property_sorter.py
```

- Step 2: enumerate all candidates and generate signatures
```
python run_combo_generator.py
```


### Signature refining

*choose between different methods*
```
[combo_selection]
; choose from best-remaining or threshold
combo_selection_approach = best-remaining
```

- Step 1 (for threshold-based method): sort signatures based on their own contributions
```
python run_combo_sorter.py
```

- Step 2: select signatures using best-remaining or threshold based method
```
python run_combo_selection.py
```



## Signature Evaluation
*Input: property lists within time range*
```
[combo_evaluation]
start_date = 2020-07-16
end_date = 2020-07-31
```
*Output: check new files in folder ./dataset/combo_generation_results*

- Evaluate the generated signatures
```
python run_combo_evaluator.py
```

# License

This project is licensed under the MIT License - see the LICENSE.md file for details
