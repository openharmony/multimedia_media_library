/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
class JsonHelper {
public:
    static std::string
        GetStringFromJson(const Json::Value &data, const std::string key, const std::string defaultValue = "")
    {
        if (data.isObject() && data.isMember(key.c_str()) && data[key].isString()) {
            return data[key].asString();
        }
        return defaultValue;
    }
    static int GetIntFromJson(const Json::Value &data, const std::string key, const int defaultValue = 0)
    {
        if (data.isObject() && data.isMember(key.c_str()) && data[key].isInt()) {
            return data[key].asInt();
        }
        return defaultValue;
    }
    static uint32_t GetUIntFromJson(const Json::Value &data, const std::string key, const uint32_t defaultValue = 0)
    {
        if (data.isObject() && data.isMember(key.c_str()) && data[key].isUInt()) {
            return data[key].asUInt();
        }
        return defaultValue;
    }
    static bool GetBoolFromJson(const Json::Value &data, const std::string key, const bool defaultValue = false)
    {
        if (data.isObject() && data.isMember(key.c_str()) && data[key].isBool()) {
            return data[key].asBool();
        }
        return defaultValue;
    }
    static uint64_t GetUInt64FromJson(const Json::Value &data, const std::string key, const uint64_t defaultValue = 0)
    {
        if (data.isObject() && data.isMember(key.c_str()) && data[key].isUInt64()) {
            return data[key].asUInt64();
        }
        return defaultValue;
    }
    static int64_t GetInt64FromJson(const Json::Value &data, const std::string key, const int64_t defaultValue = 0)
    {
        if (data.isObject() && data.isMember(key.c_str()) && data[key].isInt64()) {
            return data[key].asInt64();
        }
        return defaultValue;
    }
    static double GetDoubleFromJson(const Json::Value &data, const std::string key, const double defaultValue = 0)
    {
        if (data.isObject() && data.isMember(key.c_str()) && data[key].isDouble()) {
            return data[key].asDouble();
        }
        return defaultValue;
    }
    static std::string JsonToString(const Json::Value &data)
    {
        Json::StreamWriterBuilder writerBuilder;
        writerBuilder["indentation"] = "";
        return Json::writeString(writerBuilder, data);
    }
    static Json::Value StringToJson(const std::string &data)
    {
        Json::Value jsValue;
        Json::CharReaderBuilder builder;
        Json::CharReader *reader = builder.newCharReader();
        if (reader == nullptr) {
            return jsValue;
        }
        std::string errors;
        if (!reader->parse(data.c_str(), data.c_str() + data.size(), &jsValue, &errors)) {
            delete reader;
            return jsValue;
        }
        delete reader;
        return jsValue;
    }
    static std::string JsonArrayToString(const Json::Value &data, const std::string &sep)
    {
        std::string out = "";
        if (!data.isArray()) {
            return out;
        }
        for (Json::ArrayIndex i = 0; i < data.size(); ++i) {
            if (!data[i].isString()) {
                continue;
            }
            out.append(data[i].asString());
            if (i + 1 < data.size()) {
                out.append(sep);
            }
        }
        return out;
    }

    static bool JsonToStrVec(const Json::Value &data, std::vector<std::string> &vec)
    {
        if (!data.isArray()) {
            return false;
        }
        for (Json::ArrayIndex i = 0; i < data.size(); ++i) {
            if (!data[i].isString()) {
                continue;
            }
            vec.emplace_back(data[i].asString());
        }
        return vec.empty() ? false : true;
    }

    static bool HasSpecifiedKey(const Json::Value &data, const std::string &key)
    {
        if (data.isObject() && data.isMember(key.c_str())) {
            return true;
        }
        return false;
    }
};
#endif