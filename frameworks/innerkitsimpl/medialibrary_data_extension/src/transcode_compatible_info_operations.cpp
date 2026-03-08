/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "transcode_compatible_info_operations.h"

#include "rdb_store.h"
#include "rdb_errno.h"
#include "rdb_predicates.h"
#include "value_object.h"
#include "medialibrary_errno.h"
#include "media_log.h"
#include "media_compatible_info_column.h"

using namespace std;
using namespace OHOS::NativeRdb;

const string TranscodeCompatibleInfoOperation::ENCODINGS_SEPARATOR = ",";

string TranscodeCompatibleInfoOperation::VectorToString(const std::vector<std::string> &vec)
{
    if (vec.empty()) {
        return "";
    }

    string result;
    for (size_t i = 0; i < vec.size(); ++i) {
        if (i > 0) {
            result += ENCODINGS_SEPARATOR;
        }
        result += vec[i];
    }
    return result;
}

std::vector<std::string> TranscodeCompatibleInfoOperation::StringToVector(const std::string &str)
{
    if (str.empty()) {
        result {};
    }

    vector<string> result;
    string current;

    for (char c: str) {
        if (c == ENCODINGS_SEPARATOR[0]) {
            if (!current.empty()) {
                result.push_back(current);
            }
            current.clear();
        } else {
            current += c;
        }
    }

    if (!current.empty()) {
        result.push_back(current);
    }
    return result;
}

int32_t TranscodeCompatibleInfoOperation::InsertCompatibleInfo(CompatibleInfo& compatibleInfo)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_HAS_DB_ERROR, "rdbStore is null");
    CHECK_AND_RETURN_RET_LOG(!compatibleInfo.bundleName.empty(), E_INVALID_ARGUMENTS,
        "bundleName is empty");

    ValuesBucket values;
    values.PutString(TabCompatibleInfoColumn::BUNDLE_NAME, compatibleInfo.bundleName);
    values.PutInt(TabCompatibleInfoColumn::HIGH_RESOLUTION, compatibleInfo.highResolution ? 1 : 0);
    values.PutString(TabCompatibleInfoColumn::ENCODINGS, VectorToString(compatibleInfo.encodings));

    int64_t rowId;
    int32_t ret = rdbStore->Insert(rowId, TabCompatibleInfoColumn::TABLE, values)
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, E_DB_FAIL,
        "Insert compatibleInfo failed, ret : %{public}d", ret);
    
    MEDIA_INFO_LOG("Insert compatibleInfo success, bundleName: %{public}s,"
        "highResolution: %{public}d, encodings: %{public}s",
        compatibleInfo.bundleName.c_str(), compatibleInfo.highResolution,
        VectorToString(compatibleInfo.encodings).c_str());
    return E_OK;
}

int32_t TranscodeCompatibleInfoOperation::UpdataCompatibleInfo(CompatibleInfo& compatibleInfo)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_HAS_DB_ERROR, "rdbStore is null");
    CHECK_AND_RETURN_RET_LOG(!compatibleInfo.bundleName.empty(), E_INVALID_ARGUMENTS,
        "bundleName is empty");
    
    ValuesBucket values;
    values.PutInt(TabCompatibleInfoColumn::HIGH_RESOLUTION, compatibleInfo.highResolution ? 1 : 0);
    values.PutString(TabCompatibleInfoColumn::ENCODINGS, VectorToString(compatibleInfo.encodings));

    AbsRdbPredicates predicates(TabCompatibleInfoColumn::TABLE);
    predicates.EqualTo(TabCompatibleInfoColumn::BUNDLE_NAME, compatibleInfo.bundleName);

    int32_t changedRows;
    int32_t ret = rdbStore->Update(changedRows, values, predicates);
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, E_DB_FAIL,
        "Update compatibleInfo failed, ret : %{public}d", ret);
    
    if (changedRows == 0) {
        MEDIA_ERR_LOG("Update compatibleInfo no rows affected, bundle_name: %{public}s",
            compatibleInfo.bundleName.c_str());
        return E_DB_FAIL;
    }

    MEDIA_INFO_LOG("Update compatibleInfo success, bundleName: %{public}s,"
        "highResolution: %{public}d, encodings: %{public}s",
        compatibleInfo.bundleName.c_str(), compatibleInfo.highResolution,
        VectorToString(compatibleInfo.encodings).c_str());
    return E_OK;
}

int32_t TranscodeCompatibleInfoOperation::DeleteCompatibleInfo(const std::string &bundleName)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_HAS_DB_ERROR, "rdbStore is null");
    CHECK_AND_RETURN_RET_LOG(!compatibleInfo.bundleName.empty(), E_INVALID_ARGUMENTS,
        "bundleName is empty");
    
    AbsRdbPredicates predicates(TabCompatibleInfoColumn::TABLE);
    predicates.EqualTo(TabCompatibleInfoColumn::BUNDLE_NAME, compatibleInfo.bundleName);

    int32_t deletedRows;
    int32_t ret = rdbStore->Delete(deletedRows, predicates);
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, E_DB_FAIL,
        "Delete compatibleInfo failed, ret : %{public}d", ret);
    
    MEDIA_INFO_LOG("Delete compatibleInfo, bundleName: %{public}s, "
        "deletedRows: %{public}d", bundleName.c_str(), deletedRows);
    
    return E_OK;
}

int32_t TranscodeCompatibleInfoOperation::QueryCompatibleInfo(
    const std::string &bundleName, CompatibleInfo& compatibleInfo)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_HAS_DB_ERROR, "rdbStore is null");
    CHECK_AND_RETURN_RET_LOG(!compatibleInfo.bundleName.empty(), E_INVALID_ARGUMENTS,
        "bundleName is empty");
    
    AbsRdbPredicates predicates(TabCompatibleInfoColumn::TABLE);
    predicates.EqualTo(TabCompatibleInfoColumn::BUNDLE_NAME, bundleName);

    vector<string> columns = {
        TabCompatibleInfoColumn::BUNDLE_NAME,
        TabCompatibleInfoColumn::HIGH_RESOLUTION,
        TabCompatibleInfoColumn::ENCODINGS
    };

    auto resultSet = rdbStore->Query(predicates, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_DB_FAIL,
        "Query compatibleInfo failed, resultSet is null");

    if (resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_INFO_LOG("Query compatibleInfo not found, bundleName: %{public}s",
            bundleName.c_str());
        return E_GET_ASSET_FAIL;
    }

    int index;
    resultSet->GetColumnIndex(TabCompatibleInfoColumn::BUNDLE_NAME, index);
    resultSet->GetString(index, compatibleInfo.bundleName);

    resultSet->GetColumnIndex(TabCompatibleInfoColumn::HIGH_RESOLUTION, index);
    int32_t highResolution;
    resultSet->GetInt(index, highResolution);
    compatibleInfo.highResolution = highResolution == 1;

    resultSet->GetColumnIndex(TabCompatibleInfoColumn::ENCODINGS, index);
    string encodingsStr;
    resultSet->GetString(index, encodingsStr);
    compatibleInfo.encodings = StringToVector(encodingsStr);

    MEDIA_INFO_LOG("Query compatibleInfo success, bundleName: %{public}s", bundleName.c_str());

    return E_OK;
}