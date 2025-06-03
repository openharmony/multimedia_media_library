/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef JSON_HELPER_H
#define JSON_HELPER_H

#include "json/json.h"
#include <string>
#include "cloud_media_define.h"

class EXPORT JsonHelper {
public:
    static std::string GetStringFromJson(
        const Json::Value &data, const std::string key, const std::string defaultValue = "");
    static int GetIntFromJson(const Json::Value &data, const std::string key, const int defaultValue = 0);
    static uint32_t GetUIntFromJson(const Json::Value &data, const std::string key, const uint32_t defaultValue = 0);
    static bool GetBoolFromJson(const Json::Value &data, const std::string key, const bool defaultValue = false);
    static uint64_t GetUInt64FromJson(const Json::Value &data, const std::string key, const uint64_t defaultValue = 0);
    static int64_t GetInt64FromJson(const Json::Value &data, const std::string key, const int64_t defaultValue = 0);
    static double GetDoubleFromJson(const Json::Value &data, const std::string key, const double defaultValue = 0);
    static std::string JsonToString(const Json::Value &data);
    static Json::Value StringToJson(const std::string &data);
    static std::string JsonArrayToString(const Json::Value &data, const std::string &sep);
    static bool JsonToStrVec(const Json::Value &data, std::vector<std::string> &vec);
    static bool HasSpecifiedKey(const Json::Value &data, const std::string &key);
};
#endif