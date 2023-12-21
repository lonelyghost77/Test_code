import fasttext
import re
import numpy as np
import os
import pickle
import tensorflow as tf
import shutil

from app import logger
from app.base import AppLogic, ModelDesc, RequiredData, ModelData, QueryResult, EndpointDesc, HttpMethod
from catboost import CatBoostClassifier
from typing import Union, TypeVar, Any, Optional, Sequence, Callable
from sklearn.ensemble import RandomForestClassifier
from zipfile import ZipFile
from lightgbm import LGBMClassifier
from sklearn.linear_model import LogisticRegression

ProbaEstimates = TypeVar("ProbaEstimates", bound=np.ndarray[np.ndarray[float]])
PredictLabels = TypeVar("PredictLabels", bound=np.ndarray[int])
DecoratedCallable = TypeVar("DecoratedCallable", bound=Callable[..., Any])
ModelObject = TypeVar("ModelObject", bound=Union[fasttext.FastText | tf.keras.models.Model | CatBoostClassifier])


class PowerShellMalDetImpl(AppLogic):
    # Name of the models, as they will be requested in the database.
    __fts_code: str = "FTS"
    __fte_code: str = "FTE"
    __rf_man_ft2e_code: str = "RF_MAN_FT2E"
    __cb_man_ft2e_code: str = "CB_MAN_FT2E"
    __pmdas_code: str = "PMDAS"
    __meta_lgb_code: str = 'META_LGB'
    __meta_logreg_code: str = 'META_LOGREG'
    # Регулярное выражение для IPv4
    __ipv4_regex: str = r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
    __MAX_TOKEN_COUNT: int = 2000  # Максимальное количество токенов в PowerShell скрипте

    def __init__(self):
        super().__init__("ML/DL model for classification malicious PowerShell scripts.")
        self.__fts_model: Optional[fasttext.FastText] = None
        self.__fte_model: Optional[fasttext.FastText] = None
        self.__rf_man_ft2e_model: Optional[RandomForestClassifier] = None
        self.__cb_man_ft2e_model: Optional[CatBoostClassifier] = None
        self.__pmdas_model: Optional[tf.keras.models.Model] = None
        self.__meta_lgb_model: Optional[LGBMClassifier] = None
        self.__meta_logreg_model: Optional[LogisticRegression] = None

    @staticmethod
    def creating_file_from_binary_data(data: bytearray, file_name: str) -> None:
        """Creates a file with the specified name from a binary array.

        :param data: a data file stored as a binary array.
        :param file_name: The full name by which the file will be created.

        :return: None.
        """
        with open(file_name, 'wb') as file:
            file.write(data)

    @staticmethod
    def __load_model(func: DecoratedCallable) -> DecoratedCallable:
        def wrapper(data: bytearray, file_name: str) -> ModelObject:
            """ The wrapper function creates a file stored as a binary array, passes the file name to the main one
             function and deletes the created files.

            :param data: A file stored as a binary array.
            :param file_name: The name of the file that will be passed to the main function.

            :return: Returns the result of executing the function to which this decorator was variable.
            """
            all_files = set(os.listdir("./"))
            PowerShellMalDetImpl.creating_file_from_binary_data(data, file_name)
            if ".zip" in file_name:
                PowerShellMalDetImpl.unzipping(file_name)
                file_name = file_name[:-4]
            model = func(file_name)
            [os.remove(file_n) for _, file_n in enumerate(set(os.listdir("./")) - all_files) if
             os.path.isfile(file_n)]
            [shutil.rmtree(dir_name) for _, dir_name in enumerate(set(os.listdir("./")) - all_files) if
             os.path.isdir(dir_name)]
            return model

        return wrapper

    @staticmethod
    @__load_model
    def __load_tf_model(model_name: str) -> tf.keras.models.Model:
        """Loads the model as a Keras object.

        :param model_name: Model name, as it is called in the database.

        :return: Loaded Keras model.
        """
        return tf.keras.models.load_model(model_name)

    @staticmethod
    @__load_model
    def __load_ft_model(model_name: str) -> fasttext.FastText:
        """Loads the model as a FastText object.

        :param model_name: Model name, as it is called in the database.

        :return: Loaded FastText model.
        """
        return fasttext.load_model(f"{model_name.replace('.ftz', '')}.ftz")

    @staticmethod
    @__load_model
    def __load_catboost_model(model_name: str) -> CatBoostClassifier:
        return CatBoostClassifier().load_model(model_name)

    @staticmethod
    def unzipping(full_file_name: str) -> None:
        """Unpacks a zip archive into the current directory.

        :param full_file_name: The path where the zip archive is located.

        :return: None.
        """
        with ZipFile(full_file_name, 'r') as zObject:
            zObject.extractall()

    # overrided
    def required_data(self) -> RequiredData:
        return RequiredData([ModelDesc.from_code(self.__fts_code),
                             ModelDesc.from_code(self.__fte_code),
                             ModelDesc.from_code(self.__rf_man_ft2e_code),
                             ModelDesc.from_code(self.__cb_man_ft2e_code),
                             ModelDesc.from_code(self.__pmdas_code),
                             ModelDesc.from_code(self.__meta_lgb_code),
                             ModelDesc.from_code(self.__meta_logreg_code)], [])

    # overrided
    def on_required_data(self, models: dict[str, ModelData], data: dict[str, QueryResult]) -> None:
        if fts_data := models.get(self.__fts_code, None):
            self.__fts_model = self.__load_ft_model(fts_data.data, f"{self.__fts_code}.ftz")
            logger.info(f"Model '{fts_data.name}:{fts_data.version}' loaded successfully")
        if fte_data := models.get(self.__fte_code, None):
            self.__fte_model = self.__load_ft_model(fte_data.data, f"{self.__fte_code}.zip")
            logger.info(f"Model '{fte_data.name}:{fte_data.version}' loaded successfully")
        if rf_man_ft2e_data := models.get(self.__rf_man_ft2e_code, None):
            self.__rf_man_ft2e_model = pickle.loads(rf_man_ft2e_data.data)
            logger.info(f"Model '{rf_man_ft2e_data.name}:{rf_man_ft2e_data.version}' loaded successfully")
        if cb_man_ft2e_data := models.get(self.__cb_man_ft2e_code, None):
            self.__cb_man_ft2e_model = self.__load_catboost_model(cb_man_ft2e_data.data,
                                                                  f"{self.__cb_man_ft2e_code}.cbm")
            logger.info(f"Model '{cb_man_ft2e_data.name}:{cb_man_ft2e_data.version}' loaded successfully")
        if pmdas_data := models.get(self.__pmdas_code, None):
            self.__pmdas_model = self.__load_tf_model(pmdas_data.data, f"{self.__pmdas_code}.zip")
            logger.info(f"Model '{pmdas_data.name}:{pmdas_data.version}' loaded successfully")
        if meta_lgb_data := models.get(self.__meta_lgb_code, None):
            self.__meta_lgb_model = pickle.loads(meta_lgb_data.data)
            logger.info(f"Model '{meta_lgb_data.name}:{meta_lgb_data.version}' loaded successfully")
        if meta_logreg_data := models.get(self.__meta_logreg_code, None):
            self.__meta_logreg_model = pickle.loads(meta_logreg_data.data)
            logger.info(f"Model '{meta_logreg_data.name}:{meta_logreg_data.version}' loaded successfully")

    # overrided
    def endpoints(self) -> list[EndpointDesc]:
        return [
            EndpointDesc("/service/fts_check_mal_powershell", self.__fts_check, HttpMethod.POST),
            EndpointDesc("/service/rf_man_ft2e_check_mal_powershell", self.__rf_man_ft2e_check, HttpMethod.POST),
            EndpointDesc("/service/cb_man_ft2e_check_mal_powershell", self.__cb_man_ft2e_check, HttpMethod.POST),
            EndpointDesc("/service/pmdas_check_mal_powershell", self.__pmdas_check, HttpMethod.POST),
            EndpointDesc("/service/meta_lgb_check_mal_powershell", self.__meta_lgb_check, HttpMethod.POST),
            EndpointDesc("/service/meta_logreg_check_mal_powershell", self.__meta_logreg_check, HttpMethod.POST)

        ]

    def __fts_check(self, in_data: list[str]) -> list[int]:
        """The result is a prediction of the FastText model class related to the incoming PowerShell competitive scripts.

        :param in_data: List of PowerShell scripts.

        :return: List with predicted class labels.
        """
        self.__check_work((self.__fts_model,), (self.__fts_code,), in_data)  # Work check
        semantic_features = list(map(lambda script: self.__data_to_tokens(script), in_data))
        return self.ft_predict_and_proba(self.__fts_model, semantic_features)[0].tolist()

    def __rf_man_ft2e_check(self, in_data: list[str]) -> list[int]:
        """Gets the class's prediction from the RandomForest model whether the PowerShell input is a malicious script.

        :param in_data: List of PowerShell scripts.

        :return: List with predicted class labels.
        """
        # Health check
        self.__check_work((self.__fte_model, self.__rf_man_ft2e_model),
                          (self.__fte_code, self.__rf_man_ft2e_code),
                          in_data)

        # Obtaining hybrid features
        hybrid_features = tuple(map(lambda script: self.__get_hybrid_features(self.__fte_model, script), in_data))
        return self.sklearn_like_model_predict(self.__rf_man_ft2e_model, hybrid_features).tolist()

    def __cb_man_ft2e_check(self, in_data: list[str]) -> list[int]:
        """Gets the PMDAS model's class prediction of whether incoming PowerShell scripts are malicious scripts.

        :param in_data: List of PowerShell scripts.

        :return: List with predicted class labels.
        """
        # Health check
        self.__check_work((self.__fte_model, self.__cb_man_ft2e_model),
                          (self.__fte_code, self.__cb_man_ft2e_code),
                          in_data)
        # Obtaining hybrid features
        hybrid_features = list(map(lambda script: self.__get_hybrid_features(self.__fte_model, script), in_data))
        return self.sklearn_like_model_predict(self.__cb_man_ft2e_model, hybrid_features).tolist()

    def __pmdas_check(self, in_data: list[str]) -> list[int]:
        """Gets the PMDAS model's class prediction of whether incoming PowerShell scripts are malicious scripts.

        :param in_data: List of PowerShell scripts.

        :return: List with predicted class labels.
        """
        # Health check
        self.__check_work((self.__pmdas_model,), (self.__pmdas_code,), in_data)
        semantic_features = list(map(lambda script: self.__data_to_tokens(script, self.__MAX_TOKEN_COUNT), in_data))
        return self.tf_like_model_predict(self.__pmdas_model, semantic_features).tolist()

    def __meta_lgb_check(self, in_data: list[str]) -> list[int] | int:
        """Gets a prediction of the class label by the meta-model (Gradient Boosting) whether the incoming
         PowerShell to malicious scripts.

        :param in_data: List of PowerShell scripts.

        :return: List with predicted class labels.
        """
        # Health check
        self.__check_work((self.__fte_model,
                           self.__fts_model,
                           self.__rf_man_ft2e_model,
                           self.__cb_man_ft2e_model,
                           self.__pmdas_model,
                           self.__meta_lgb_model),
                          (self.__fte_code,
                           self.__fts_code,
                           self.__rf_man_ft2e_code,
                           self.__cb_man_ft2e_code,
                           self.__meta_lgb_code),
                          in_data)
        # Meta signs
        meta_features = self.__get_meta_features(in_data)
        return self.sklearn_like_model_predict(self.__meta_lgb_model, meta_features).tolist()

    def __meta_logreg_check(self, in_data: list[str]) -> list[int] | int:
        """Gets the meta-model's (logistic regression) prediction of the class label whether the incoming class belongs
        to PowerShell to malicious scripts.

        :param in_data: List of PowerShell scripts.

        :return: List with predicted class labels.
        """
        # Health check
        self.__check_work((self.__fte_model,
                           self.__fts_model,
                           self.__rf_man_ft2e_model,
                           self.__cb_man_ft2e_model,
                           self.__pmdas_model,
                           self.__meta_logreg_model),
                          (self.__fte_code,
                           self.__fts_code,
                           self.__rf_man_ft2e_code,
                           self.__cb_man_ft2e_code,
                           self.__meta_logreg_code),
                          in_data)
        # Meta signs
        meta_features = self.__get_meta_features(in_data)
        return self.sklearn_like_model_predict(self.__meta_logreg_model, meta_features).tolist()

    @staticmethod
    def __check_work(models: Sequence[...], model_names: Sequence[str], in_data: list[str]):
        mask = [i for i, data in enumerate(models) if not bool(data)]
        # Checking that models are loaded
        if not all(models):
            raise Exception(f"Model/s not loaded: {np.array(model_names)[mask]}")
        # Check that the data arrived in acceptable form
        if not all(map(lambda script: isinstance(script, str) and len(script) > 0, in_data)):
            raise ValueError("Invalid input data")

    @staticmethod
    def ft_predict_and_proba(model: Any, in_data: list[str]) -> tuple[PredictLabels, ProbaEstimates]:
        """Gets the predicted class by the FastText model and the probability of that class.

        :param model: FastText model (supervised learning)
        :param in_data: A list with a line above which a prediction should be made.
        :return:
        """
        ft_out = model.predict(in_data)  # Prediction (tuple with labels and probabilities) of the model
        labels = np.array(ft_out[0]).flatten()  # Array with class labels
        # Array with inverted class labels
        labels = np.vectorize(lambda x: int(x.replace('__label__1', '0').replace('__label__0', '1')))(labels)
        probs = np.array(ft_out[1]).flatten()  # Array with probabilities of predicted classes
        absoluete_value = np.abs(labels - probs)  # To separate probabilities by class
        return np.abs(labels - 1), np.column_stack((1 - absoluete_value, absoluete_value))

    @staticmethod
    def sklearn_like_model_predict_proba(model: Any, in_data: Sequence[Sequence[int | float]]) -> ProbaEstimates:
        """Predict probability using the scikit-learn like estimators.

        :param model: scikit-learn like estimators.
        :param in_data: Features for label prediction.

        :return: Array with class membership probabilities.
        """
        return model.predict_proba(in_data)

    @staticmethod
    def sklearn_like_model_predict(model: Any, in_data: Sequence[Sequence[int | float]]) -> PredictLabels:
        """Predict using the scikit-learn like estimators.

        :param model: scikit-learn like estimators.
        :param in_data: Features for label prediction.

        :return: An array containing class labels.
        """
        return model.predict(in_data)

    @staticmethod
    def tf_like_model_predict_proba(model: Any, in_data: list[str]) -> ProbaEstimates:
        """Predict probability using the TensorFlow like model.

        :param model: TensorFlow like model
        :param in_data: A list with a line above which a prediction should be made.

        :return: An array containing class labels.
        """
        dataset = tf.data.Dataset.from_tensor_slices(in_data).batch(16).prefetch(tf.data.AUTOTUNE)
        return model.predict(dataset)

    def tf_like_model_predict(self, model: Any, in_data: list[str]) -> PredictLabels:
        """Predict using the TensorFlow like model.

        :param model: TensorFlow like model.
        :param in_data: A list with a line above which a prediction should be made.

        :return: An array containing class labels.
        """
        probs = self.tf_like_model_predict_proba(model, in_data)
        return tf.argmax(probs, axis=1).numpy()

    def __get_meta_features(self, in_data: list[str]) -> np.ndarray[np.ndarray[float]]:
        """Method for obtaining meta-features (class prediction probability) from input data.

        :param in_data: List of unprocessed scripts.

        :return: An array containing the probabilities of class membership.
        """
        # Semantic features
        semantic_features = list(map(lambda script: self.__data_to_tokens(script), in_data))
        semantic_features_trun = list(map(lambda script: self.__truncate_string(script, self.__MAX_TOKEN_COUNT),
                                          semantic_features))
        # Hybrid traits
        hybrid_features = list(map(lambda script: self.__get_hybrid_features(self.__fte_model, script), in_data))
        # Predicted class probabilities
        fts_probs = self.ft_predict_and_proba(self.__fts_model, semantic_features)[1][:, 1]
        rf_man_ft2e_probs = self.sklearn_like_model_predict_proba(self.__rf_man_ft2e_model, hybrid_features)[:, 1]
        cb_man_ft2e_probs = self.sklearn_like_model_predict_proba(self.__cb_man_ft2e_model, hybrid_features)[:, 1]
        pmdas_probs = self.tf_like_model_predict_proba(self.__pmdas_model, semantic_features_trun)[:, 1]
        # Мета признаки
        return np.column_stack((rf_man_ft2e_probs, cb_man_ft2e_probs, fts_probs, pmdas_probs))

    @staticmethod
    def __get_hybrid_features(embed_model, in_data: str) -> np.ndarray[float]:
        """A method for obtaining hybrid features - manual features and a vector of semantic features.

        :param in_data: The input string from which the data set will be collected.

        :return: An array containing semantic features.
        """
        manual_features = PowerShellMalDetImpl.__get_manual_features(in_data)
        # Tags from FastText
        embeddings = embed_model.get_sentence_vector(PowerShellMalDetImpl.__data_to_tokens(in_data))
        return np.hstack((manual_features, embeddings))

    @staticmethod
    def __get_manual_features(in_data: str) -> tuple[Union[int | float], ...]:
        """Collects a data set with 12 features from the input string: presence of Shell code, Shannon entropy, ascii
        code 5 the most common characters in the input string, the number of lines, the length of the entire line, the
        average length of the line, number of $ characters in the input string, presence of labels for the web
        connection.

        :param in_data: The input string from which the data set will be collected.

        :return: The result is an array of 12 features.
        """
        shell_feature = int(PowerShellMalDetImpl.__check_shell_code(in_data))  # Shell code check
        char_array, char_count_array = np.unique(np.array(list(map(ord, list(in_data)))), return_counts=True)
        # Calculate Shannon entropy
        information_entropy = PowerShellMalDetImpl.__information_entropy_calculation(char_count_array)
        # Ascii code 5 most common characters
        top_five_ascii_char: np.ndarray = char_array[np.argsort(-char_count_array)][:5]
        # Number of lines in PowerShell Script
        rows_number = PowerShellMalDetImpl.__get_char_count(char_array == ord("\n"), char_count_array) + 1
        rows_max_len = len(in_data)  # Length of the entire script
        rows_avg_len = (rows_max_len / rows_number)  # Average script length
        # Number of variables in the script
        number_of_variables = PowerShellMalDetImpl.__get_char_count(char_array == ord("$"), char_count_array)
        # Presence of an IP address or url in the script
        url_or_ip = int(PowerShellMalDetImpl.__get_url_or_ip_feature(in_data))
        return (shell_feature,
                information_entropy,
                *top_five_ascii_char,
                rows_number,
                rows_max_len,
                rows_avg_len,
                number_of_variables,
                url_or_ip)

    @staticmethod
    def __check_shell_code(in_str: str) -> bool:
        """Checks for the presence of Shell code in the input line.

        :param in_str: The input string.

        :return: True или False.
        """
        return bool(re.search(r"0x\S+", in_str) or
                    re.search(r"FromBase64String\(\'(.*)\'\)", in_str) or
                    re.search(r"([a-zA-Z0-9\/\+=]{100,})+", in_str))

    @staticmethod
    def __information_entropy_calculation(char_count_array: np.ndarray[int]) -> float:
        """Calculates Shannon information entropy.

        :param char_count_array: A numpy array with the number of each character in the line.

        :return: The meaning of information entropy.
        """
        temp_calculation = char_count_array / np.sum(char_count_array)
        return -np.sum(temp_calculation * np.log2(temp_calculation))

    @staticmethod
    def __get_char_count(filter_mask: np.ndarray[bool], char_count_array: np.ndarray[int]) -> int:
        """Filters the input numpy array with unique values by the incoming Boolean mask.

        :param filter_mask: Logical mask for filtering a numpy array.
        :param char_count_array: The input numpy array.

        :return: The value from the array converted to an integer or 0.
        """
        return int([0, char_count_array[filter_mask]][filter_mask.any()])

    @staticmethod
    def __get_url_or_ip_feature(in_str: str) -> bool:
        """Checks for the presence of tags such as downloadfile, http, www and the presence of IPv4 in the input string.

        :param in_str: The string in which tags will be searched.

        :return: True if the label is found. False if the label is not found.
        """
        in_str = in_str.lower()
        return bool(re.search(r"\bdownloadfile\b", in_str) or
                    re.search(r"\bhttp\b", in_str) or
                    re.search(r".www\W", in_str) or
                    re.search(PowerShellMalDetImpl.__ipv4_regex, in_str))

    @staticmethod
    def __data_to_tokens(in_str: str, truncate: Optional[int] = None) -> str:
        """Converts the input string by encoding Base64, ShellCode, IPv4, numbers, special characters and
        repeating spaces.

         :param in_str: Term over which the conversion occurs.

         :return: Returns the converted string.
         """
        out_str = re.sub(r"FromBase64String\(\'(.*)\'\)", "base64_string", in_str, flags=re.MULTILINE)
        out_str = re.sub(r"([a-zA-Z0-9\/\+=]{100,})+", "base64_string", out_str, flags=re.MULTILINE)
        out_str = re.sub(r'[^a-zA-Z*0-9$.]', ' ', out_str, flags=re.MULTILINE)  # Removes special characters
        # Replaces individual digits with *
        out_str = re.sub(r"(?<!\S)\d+(?!\S)", "*", out_str, flags=re.MULTILINE)
        out_str = re.sub(r"0x\S+", " ", out_str)  # Replaces Shell code
        out_str = PowerShellMalDetImpl.__encodes_ipv4(out_str)  # Encodes IPv4
        out_str = out_str.replace('.', ' ')
        out_str = re.sub(r'\s+', ' ', out_str.lower())  # Encodes all repeated whitespace characters
        # Standardizes the number of tokens
        if truncate:
            out_str = PowerShellMalDetImpl.__truncate_string(out_str, truncate)
        return out_str

    @staticmethod
    def __encodes_ipv4(in_str: str) -> str:
        """Finds all IPv4 in the text using a regular expression and encodes them if internal - internal_ip, if
         external external_ip respectively.

        :param in_str: The string in which to encode IPv4.

        :return: Returns the encoded string if IPv4s were found, otherwise the original string.
        """
        internal_ip = ['192.168.', '172.16.', '127.0.', '100.64.', '10.']
        for ip in re.findall(PowerShellMalDetImpl.__ipv4_regex, in_str):
            in_str = in_str.replace(ip,
                                    ['external_ip', 'internal_ip'][any(map(lambda x: ip.startswith(x), internal_ip))])
        return in_str

    @staticmethod
    def __truncate_string(input_data: str, max_token_count: int) -> str:
        """The function trims the strings in the array to the number of tokens max_token_count.

        :param input_data: List of preprocessed scripts.
        :param max_token_count: Value in tokens.

        :return: Trimmed input lines.
        """
        tokens = input_data.split()
        return [input_data, ' '.join(tokens[:max_token_count])][len(tokens) > max_token_count]
