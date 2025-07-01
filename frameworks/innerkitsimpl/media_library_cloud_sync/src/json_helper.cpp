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
#define MLOG_TAG "Media_Client"

#include "json_helper.h"

#include <string>

#include "media_log.h"
// LCOV_EXCL_START
std::string JsonHelper::GetStringFromJson(
    const Json::Value &data, const std::string key, const std::string defaultValue)
{
    if (data.isObject() && data.isMember(key.c_str()) && data[key].isString()) {
        return data[key].asString();
    }
    return defaultValue;
}
int JsonHelper::GetIntFromJson(const Json::Value &data, const std::string key, const int defaultValue)
{
    if (data.isObject() && data.isMember(key.c_str()) && data[key].isInt()) {
        return data[key].asInt();
    }
    return defaultValue;
}
uint32_t JsonHelper::GetUIntFromJson(const Json::Value &data, const std::string key, const uint32_t defaultValue)
{
    if (data.isObject() && data.isMember(key.c_str()) && data[key].isUInt()) {
        return data[key].asUInt();
    }
    return defaultValue;
}
bool JsonHelper::GetBoolFromJson(const Json::Value &data, const std::string key, const bool defaultValue)
{
    if (data.isObject() && data.isMember(key.c_str()) && data[key].isBool()) {
        return data[key].asBool();
    }
    return defaultValue;
}
uint64_t JsonHelper::GetUInt64FromJson(const Json::Value &data, const std::string key, const uint64_t defaultValue)
{
    if (data.isObject() && data.isMember(key.c_str()) && data[key].isUInt64()) {
        return data[key].asUInt64();
    }
    return defaultValue;
}
int64_t JsonHelper::GetInt64FromJson(const Json::Value &data, const std::string key, const int64_t defaultValue)
{
    if (data.isObject() && data.isMember(key.c_str()) && data[key].isInt64()) {
        return data[key].asInt64();
    }
    return defaultValue;
}
double JsonHelper::GetDoubleFromJson(const Json::Value &data, const std::string key, const double defaultValue)
{
    if (data.isObject() && data.isMember(key.c_str()) && data[key].isDouble()) {
        return data[key].asDouble();
    }
    return defaultValue;
}
std::string JsonHelper::JsonToString(const Json::Value &data)
{
    Json::StreamWriterBuilder writerBuilder;
    writerBuilder["indentation"] = "";
    return Json::writeString(writerBuilder, data);
}
Json::Value JsonHelper::StringToJson(const std::string &data)
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
std::string JsonHelper::JsonArrayToString(const Json::Value &data, const std::string &sep)
{
    std::string out = "";
    if (!data.isArray()) {
        return out;
    }
    Json::ArrayIndex maxCount = 500;
    for (Json::ArrayIndex i = 0; i < data.size() && i < maxCount; ++i) {
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

bool JsonHelper::JsonToStrVec(const Json::Value &data, std::vector<std::string> &vec)
{
    if (!data.isArray()) {
        return false;
    }
    Json::ArrayIndex maxCount = 500;
    for (Json::ArrayIndex i = 0; i < data.size() && i < maxCount; ++i) {
        if (!data[i].isString()) {
            continue;
        }
        vec.emplace_back(data[i].asString());
    }
    return vec.empty() ? false : true;
}

bool JsonHelper::HasSpecifiedKey(const Json::Value &data, const std::string &key)
{
    if (data.isObject() && data.isMember(key.c_str())) {
        return true;
    }
    return false;
}
// LCOV_EXCL_STOP