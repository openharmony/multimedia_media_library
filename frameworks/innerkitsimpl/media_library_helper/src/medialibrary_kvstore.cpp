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

#include "medialibrary_kvstore.h"

#include <algorithm>

#include "medialibrary_errno.h"
#include "medialibrary_tracer.h"
#include "media_log.h"

using namespace OHOS::DistributedKv;
namespace OHOS::Media {
const OHOS::DistributedKv::AppId KVSTORE_APPID = {"com.ohos.medialibrary.medialibrarydata"};
const OHOS::DistributedKv::StoreId KVSTORE_MONTH_STOREID = {"medialibrary_month_astc"};
const OHOS::DistributedKv::StoreId KVSTORE_YEAR_STOREID = {"medialibrary_year_astc"};

int32_t MediaLibraryKvStore::Init(
    const KvStoreRoleType &roleType, const KvStoreValueType &valueType, const std::string &baseDir)
{
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryKvStore::InitKvStore");
    Options options;
    if (!GetKvStoreOption(options, roleType, baseDir)) {
        MEDIA_ERR_LOG("failed to GetKvStoreOption");
        return E_ERR;
    }

    MEDIA_INFO_LOG("InitKvStore baseDir %{public}s", options.group.groupDir.c_str());
    Status status;
    if (valueType == KvStoreValueType::MONTH_ASTC) {
        status = dataManager_.GetSingleKvStore(options, KVSTORE_APPID, KVSTORE_MONTH_STOREID, kvStorePtr_);
    } else if (valueType == KvStoreValueType::YEAR_ASTC) {
        status = dataManager_.GetSingleKvStore(options, KVSTORE_APPID, KVSTORE_YEAR_STOREID, kvStorePtr_);
    } else {
        MEDIA_ERR_LOG("invalid value type");
        return E_ERR;
    }

    if (status != Status::SUCCESS || kvStorePtr_ == nullptr) {
        MEDIA_ERR_LOG("init KvStore failed, status %{public}d", status);
        return static_cast<int32_t>(status);
    }
    return E_OK;
}

int32_t MediaLibraryKvStore::Insert(const std::string &key, const std::vector<uint8_t> &value)
{
    if (kvStorePtr_ == nullptr) {
        MEDIA_ERR_LOG("kvStorePtr_ is nullptr");
        return E_HAS_DB_ERROR;
    }

    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryKvStore::Insert");
    Key k(key);
    Value v(value);
    Status status = kvStorePtr_->Put(k, v);
    if (status != Status::SUCCESS) {
        MEDIA_ERR_LOG("insert failed, status %{public}d", status);
    }
    return static_cast<int32_t>(status);
}

int32_t MediaLibraryKvStore::Delete(const std::string &key)
{
    if (kvStorePtr_ == nullptr) {
        MEDIA_ERR_LOG("kvStorePtr_ is nullptr");
        return E_HAS_DB_ERROR;
    }

    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryKvStore::Delete");
    Key k(key);
    Status status = kvStorePtr_->Delete(k);
    if (status != Status::SUCCESS) {
        MEDIA_ERR_LOG("delete failed, status %{public}d", status);
    }
    return static_cast<int32_t>(status);
}

int32_t MediaLibraryKvStore::Query(const std::string &key, std::vector<uint8_t> &value)
{
    if (kvStorePtr_ == nullptr) {
        MEDIA_ERR_LOG("kvStorePtr_ is nullptr");
        return E_HAS_DB_ERROR;
    }

    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryKvStore::Query");
    Key k(key);
    Value v(value);
    Status status = kvStorePtr_->Get(k, v);
    if (status != Status::SUCCESS) {
        MEDIA_ERR_LOG("query failed, status %{public}d", status);
    }
    return static_cast<int32_t>(status);
}

void AddEmptyValue(std::vector<std::vector<uint8_t>> &values)
{
    std::vector<uint8_t> value = {};
    values.emplace_back(std::move(value));
}

void GenEmptyValues(std::vector<std::string> &batchKeys, std::vector<std::vector<uint8_t>> &values)
{
    for (size_t i = 0; i < batchKeys.size(); i++) {
        std::vector<uint8_t> value = {};
        values.emplace_back(std::move(value));
    }
}

int32_t FillBatchValues(std::vector<std::string> &batchKeys, std::vector<std::vector<uint8_t>> &values,
    std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr)
{
    DataQuery dataQuery;
    dataQuery.Between(batchKeys.back(), batchKeys.front());
    std::shared_ptr<KvStoreResultSet> resultSet;
    Status status = kvStorePtr->GetResultSet(dataQuery, resultSet);
    if (status != Status::SUCCESS || resultSet == nullptr) {
        MEDIA_ERR_LOG("GetResultSet error occur, status: %{public}d", status);
        return static_cast<int32_t>(status);
    }

    if (!resultSet->MoveToNext()) {
        // This may happen if all images in this group is not generated.
        MEDIA_ERR_LOG("ResultSet is empty.");
        GenEmptyValues(batchKeys, values);
        return static_cast<int32_t>(status);
    }
    auto begin = batchKeys.crbegin();
    auto end = batchKeys.crend();
    bool isEndOfResultSet = false;
    while (begin != end) {
        if (isEndOfResultSet) {
            AddEmptyValue(values);
            ++begin;
            continue;
        }
        Entry entry;
        status = resultSet->GetEntry(entry);
        if (status != Status::SUCCESS) {
            MEDIA_ERR_LOG("GetEntry error occur, status: %{public}d", status);
            return static_cast<int32_t>(status);
        }

        int result = std::strcmp(entry.key.ToString().c_str(), (*begin).c_str());
        if (result == 0) {
            std::vector<uint8_t>&& value = entry.value;
            values.emplace_back(std::move(value));
            ++begin;
            if (!resultSet->MoveToNext()) {
                isEndOfResultSet = true;
            }
        } else if (result < 0) {
            // This may happen if image is hidden or trashed by user.
            if (!resultSet->MoveToNext()) {
                isEndOfResultSet = true;
            }
        } else {
            // This may happen if image is not generated.
            AddEmptyValue(values);
            ++begin;
        }
    }
    status = kvStorePtr->CloseResultSet(resultSet);
    return static_cast<int32_t>(status);
}

int32_t MediaLibraryKvStore::BatchQuery(
    std::vector<std::string> &batchKeys, std::vector<std::vector<uint8_t>> &values)
{
    if (kvStorePtr_ == nullptr) {
        MEDIA_ERR_LOG("kvStorePtr_ is nullptr");
        return E_HAS_DB_ERROR;
    }

    std::sort(batchKeys.begin(), batchKeys.end(), [](std::string a, std::string b) {return a > b;});
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryKvStore::BatchQuery");
    return FillBatchValues(batchKeys, values, kvStorePtr_);
}

bool MediaLibraryKvStore::Close()
{
    if (kvStorePtr_ == nullptr) {
        MEDIA_ERR_LOG("kvStorePtr_ is nullptr");
        return true;
    }

    Status status = dataManager_.CloseKvStore(KVSTORE_APPID, kvStorePtr_);
    if (status != Status::SUCCESS) {
        MEDIA_ERR_LOG("close KvStore failed, status %{public}d", status);
        return false;
    }
    kvStorePtr_ = nullptr;
    return true;
}

bool MediaLibraryKvStore::GetKvStoreOption(
    DistributedKv::Options &options, const KvStoreRoleType &roleType, const std::string &baseDir)
{
    if (roleType == KvStoreRoleType::OWNER) {
        options.createIfMissing = true;
        options.role = RoleType::OWNER;
    } else if (roleType == KvStoreRoleType::VISITOR) {
        options.createIfMissing = false;
        options.role = RoleType::VISITOR;
    } else {
        MEDIA_ERR_LOG("GetKvStoreOption invalid role");
        return false;
    }
    options.group.groupDir = baseDir;
    options.encrypt = false;
    options.backup = false;
    options.autoSync = false;
    options.securityLevel = SecurityLevel::S3;
    options.kvStoreType = KvStoreType::LOCAL_ONLY;
    return true;
}
} // namespace OHOS::Media
