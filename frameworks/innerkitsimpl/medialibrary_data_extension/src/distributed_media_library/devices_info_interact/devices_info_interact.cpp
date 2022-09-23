/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#define MLOG_TAG "Distributed"

#include "devices_info_interact.h"
#include "application_context.h"
#include "media_log.h"
#include "medialibrary_db_const.h"
#include "medialibrary_device.h"
#include "medialibrary_errno.h"

namespace OHOS {
namespace Media {
static const std::string ML_MULTIDEV_INFO_ID = "mediaLibrayMultiDevInfoFetch";
static const std::string MEDIA_LIBRARY_SERVICE_TYPE = "characteristic.medialibrary.version";

DevicesInfoInteract::DevicesInfoInteract() : bundleName_(BUNDLE_NAME)
{
    MEDIA_DEBUG_LOG("DevicesInfoInteract::constructor");
}

DevicesInfoInteract::~DevicesInfoInteract()
{
    DistributedKv::DistributedKvDataManager kvManager;
    DistributedKv::AppId appId = { BUNDLE_NAME };
    if (kvStorePtr_ != nullptr) {
        kvManager.CloseKvStore(appId, kvStorePtr_);
        kvStorePtr_ = nullptr;
    }
    MEDIA_DEBUG_LOG("DevicesInfoInteract::deconstructor");
}

void DevicesInfoInteract::Init()
{
    auto context = AbilityRuntime::Context::GetApplicationContext();
    if (context == nullptr) {
        MEDIA_ERR_LOG("context is null");
        return;
    }
    DistributedKv::DistributedKvDataManager kvManager;
    DistributedKv::Options options = {
        .createIfMissing = true,
        .persistent = true,
        .backup = true,
        .autoSync = true,
        .securityLevel = DistributedKv::SecurityLevel::NO_LABEL,
        .area = DistributedKv::Area::EL2,
        .kvStoreType = DistributedKv::KvStoreType::SINGLE_VERSION,
        .baseDir = context->GetDatabaseDir()
    };
    DistributedKv::AppId appId = { BUNDLE_NAME };
    DistributedKv::StoreId storeId = { ML_MULTIDEV_INFO_ID };
    DistributedKv::Status status = kvManager.GetSingleKvStore(options, appId, storeId, kvStorePtr_);
    if (status != DistributedKv::Status::SUCCESS) {
        MEDIA_ERR_LOG("KvStore get failed! %{public}d", status);
        return;
    }
    MEDIA_INFO_LOG("KvStore using for %{public}s init success!", ML_MULTIDEV_INFO_ID.c_str());
}

std::string DevicesInfoInteract::GenerateKey(const std::string &udid)
{
    return (udid + bundleName_ + MEDIA_LIBRARY_SERVICE_TYPE);
}

void DevicesInfoInteract::SyncMLDeviceInfos(const std::string &udid, const std::string &devId)
{
    if (kvStorePtr_ == nullptr) {
        MEDIA_ERR_LOG("kvstore is nullptr");
        return;
    }

    std::string key = GenerateKey(udid);
    DistributedKv::DataQuery dataQuery;
    dataQuery.KeyPrefix(key);
    std::vector<std::string> deviceIds = { devId };
    DistributedKv::Status status = kvStorePtr_->Sync(deviceIds, DistributedKv::SyncMode::PULL,
        dataQuery, shared_from_this());
    MEDIA_ERR_LOG("kvstore sync end, status %{public}d", status);
}

bool DevicesInfoInteract::GetMLDeviceInfos(const std::string &udid, std::string &val)
{
    if (kvStorePtr_ == nullptr) {
        MEDIA_ERR_LOG("kvstore is nullptr");
        return false;
    }

    std::string key = GenerateKey(udid);

    DistributedKv::Key k(key);
    DistributedKv::Value v;
    DistributedKv::Status status = kvStorePtr_->Get(k, v);
    if (status != DistributedKv::Status::SUCCESS) {
        MEDIA_ERR_LOG("get kvstore failed %{public}d", status);
        val = MEDIA_LIBRARY_VERSION;
        return false;
    }
    std::string versionInfo = v.ToString();
    nlohmann::json jsonObj = nlohmann::json::parse(versionInfo);
    if (jsonObj.is_discarded()) {
        MEDIA_ERR_LOG("parse json failed");
        val = MEDIA_LIBRARY_VERSION;
        return false;
    }
    val = jsonObj.at("medialibrary_version");
    MEDIA_INFO_LOG("get kvstore success! ml version info %{public}s, val %{public}s",
        versionInfo.c_str(), val.c_str());
    return true;
}

void DevicesInfoInteract::PutMLDeviceInfos(const std::string &udid)
{
    if (kvStorePtr_ == nullptr) {
        MEDIA_ERR_LOG("kvstore is nullptr");
        return;
    }

    std::string key = GenerateKey(udid);
    nlohmann::json json;
    json["medialibrary_version"] = MEDIA_LIBRARY_VERSION;
    std::string val = json.dump();

    DistributedKv::Key k(key);
    DistributedKv::Value v(val);
    DistributedKv::Status status = kvStorePtr_->Put(k, v);
    if (status != DistributedKv::Status::SUCCESS) {
        MEDIA_ERR_LOG("put kvstore failed %{public}d", status);
        return;
    }
    MEDIA_INFO_LOG("put kvstore success!, val %{public}s", val.c_str());
}

void DevicesInfoInteract::SyncCompleted(const std::map<std::string, DistributedKv::Status> &results)
{
    for (auto &[devId, status] : results) {
        MediaLibraryDevice::GetInstance()->OnSyncCompleted(devId, status);
    }
}
} // namespace Media
} // namespace OHOS
