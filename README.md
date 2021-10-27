## Prerequisites
Python 3

## Dataset
./dataset/property_lists_raw folder contains a couple of example files. 

**To get the complete dataset, please email data-set@paloaltonetworks.com**


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
```

*Output: ./dataset/property_index_mapping.json*

- Step 2: convert property lists into integers
```
python run_integer_converter.py
```
*Output: ./dataset/property_lists_integer*


## Signature Generation
*Input: property lists within time range*
```
[combo_generation]
start_date = 2020-07-01
end_date = 2020-07-15
```

### Signature creation
*choose different generation mode in config file ./config/common_config.ini*:
```
[combo_generation]
; choose from:
; ablation_study
; multi_processing
; store_parent_hits
; prestore (hashes-per-property)
generation_mode = multi_processing
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
*Output: ./dataset/combo_generation_results/start-2020-07-*.end-2020-07-*.propertySorting-mfibf/sorted-properties.csv*

- Step 2: enumerate all candidates and generate signatures
```
python run_combo_generator.py
```
*Output: ./dataset/combo_generation_results/start-2020-07-*.end-2020-07-*.propertySorting-mfibf/minThres-*.maxThres-*.minComboSize-*.maxComboSize-*.generationMode-*/generated-combos.csv*


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
*Output: ./dataset/combo_generation_results/start-2020-07-\*.end-2020-07-\*.propertySorting-mfibf/minThres-\*.maxThres-\*.minComboSize-\*.maxComboSize-\*.generationMode-\*/generated-combos.csv.sorted-mfibf.csv*

- Step 2: select signatures using best-remaining or threshold based method
```
python run_combo_selection.py
```
*Output: ./dataset/combo_generation_results/start-2020-07-\*.end-2020-07-\*.propertySorting-mfibf/minThres-\*.maxThres-\*.minComboSize-\*.maxComboSize-\*.generationMode-\*/generated-combos.csv.best-remaining.rank-mfibf.selected-1.0.csv
or ./dataset/combo_generation_results/start-2020-07-\*.end-2020-07-\*.propertySorting-mfibf/minThres-\*.maxThres-\*.minComboSize-\*.maxComboSize-\*.generationMode-\*/generated-combos.csv.sorted-mfibf.csv.threshold.rank-mfibf.selected-1.0.csv*



## Signature Evaluation
*Input: property lists within time range*
```
[combo_evaluation]
start_date = 2020-07-16
end_date = 2020-07-31
```
- Evaluate the generated signatures
```
python run_combo_evaluator.py
```
*Output: combo_generation_results/start-2020-07-\*.end-2020-07-\*.propertySorting-mfibf/minThres-\*.maxThres-\*.minComboSize-\*.maxComboSize-\*.generationMode-\*/generated-combos.csv.best-remaining(threshold).rank-mfibf.selected-1.0.csv.eval-start-2020-07-\*.end-2020-07-\*.csv*

# License

This project is licensed under the MIT License - see the LICENSE.md file for details