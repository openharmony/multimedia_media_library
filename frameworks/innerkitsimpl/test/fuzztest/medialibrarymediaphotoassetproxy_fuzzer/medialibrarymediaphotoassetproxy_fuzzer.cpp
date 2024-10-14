/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "medialibrarymediaphotoassetproxy_fuzzer.h"

#include <cstdint>
#include <memory>
#include <string>

#define private public
#include "media_photo_asset_proxy.h"
#undef private

#include "ability_context_impl.h"
#include "datashare_predicates.h"
#include "iservice_registry.h"
#include "media_log.h"
#include "medialibrary_command.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_errno.h"
#include "medialibrary_unistore.h"
#include "medialibrary_unistore_manager.h"
#include "rdb_store.h"
#include "system_ability_definition.h"
#include "userfilemgr_uri.h"

namespace OHOS {
using namespace std;
using namespace DataShare;
constexpr int FUZZ_STORAGE_MANAGER_MANAGER_ID = 5003;
std::shared_ptr<DataShare::DataShareHelper> sDataShareHelper_ = nullptr;
std::shared_ptr<NativeRdb::RdbStore> g_rdbStore;
static inline int32_t FuzzInt32(const uint8_t *data, size_t size)
{
    return static_cast<int32_t>(*data);
}

static inline uint32_t FuzzUInt32(const uint8_t *data)
{
    return static_cast<uint32_t>(*data);
}

static inline double FuzzDouble(const uint8_t *data, size_t size)
{
    return static_cast<double>(*data);
}

static inline string FuzzString(const uint8_t *data, size_t size)
{
    return {reinterpret_cast<const char*>(data), size};
}

static inline Media::CameraShotType FuzzCameraShotType(const uint8_t *data, size_t size)
{
    uint8_t length = static_cast<uint8_t>(Media::CameraShotType_FUZZER_LISTS.size());
    if (*data < length) {
        return Media::CameraShotType_FUZZER_LISTS[*data];
    }
    return Media::CameraShotType::IMAGE;
}

static inline Media::PhotoFormat FuzzPhotoFormat(const uint8_t *data, size_t size)
{
    uint8_t length = static_cast<uint8_t>(Media::PhotoFormat_FUZZER_LISTS.size());
    if (*data < length) {
        return Media::PhotoFormat_FUZZER_LISTS[*data];
    }
    return Media::PhotoFormat::RGBA;
}

static inline Media::PhotoQuality FuzzPhotoQuality(const uint8_t *data, size_t size)
{
    uint8_t length = static_cast<uint8_t>(Media::PhotoQuality_FUZZER_LISTS.size());
    if (*data < length) {
        return Media::PhotoQuality_FUZZER_LISTS[*data];
    }
    return Media::PhotoQuality::HIGH;
}

static inline int32_t FuzzPhotoSubType(const uint8_t* data, size_t size)
{
    int32_t value = FuzzInt32(data, size);
    if (value >= static_cast<int32_t>(Media::PhotoSubType::DEFAULT) &&
        value <= static_cast<int32_t>(Media::PhotoSubType::SUBTYPE_END)) {
        return value;
    }
    return static_cast<int32_t>(Media::PhotoSubType::CAMERA);
}

void CreateDataHelper(int32_t systemAbilityId)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        MEDIA_ERR_LOG("Get system ability mgr failed.");
        return;
    }
    auto remoteObj = saManager->GetSystemAbility(systemAbilityId);
    if (remoteObj == nullptr) {
        MEDIA_ERR_LOG("GetSystemAbility Service Failed.");
        return;
    }

    if (sDataShareHelper_ == nullptr) {
        const sptr<IRemoteObject> &token = remoteObj;
        sDataShareHelper_ = DataShare::DataShareHelper::Creator(token, Media::MEDIALIBRARY_DATA_URI);
    }
}

static shared_ptr<Media::PhotoAssetProxy> Init(const uint8_t *data, size_t size)
{
    shared_ptr<Media::PhotoAssetProxy> photoAssetProxy = make_shared<Media::PhotoAssetProxy>(sDataShareHelper_,
        FuzzCameraShotType(data, size), FuzzInt32(data, size), FuzzInt32(data, size));
    return photoAssetProxy;
}

static sptr<Media::PhotoProxyFuzzTest> FuzzPhotoAssetProxy(const uint8_t *data, size_t size)
{
    sptr<Media::PhotoProxyFuzzTest> photoProxyFuzzTest = new(std::nothrow) Media::PhotoProxyFuzzTest();
    if (photoProxyFuzzTest == nullptr) {
        return nullptr;
    }
    photoProxyFuzzTest->SetFormat(FuzzPhotoFormat(data, size));
    photoProxyFuzzTest->SetPhotoQuality(FuzzPhotoQuality(data, size));

    return photoProxyFuzzTest;
}

static void MediaLibraryMediaPhotoAssetProxyTest(const uint8_t *data, size_t size)
{
    if (sDataShareHelper_ == nullptr) {
        CreateDataHelper(FUZZ_STORAGE_MANAGER_MANAGER_ID);
    }
    shared_ptr<Media::PhotoAssetProxy> photoAssetProxy = Init(data, size);
    if (photoAssetProxy == nullptr) {
        return;
    }

    sptr<Media::PhotoProxyFuzzTest> photoProxyFuzzTest = FuzzPhotoAssetProxy(data, size);

    photoAssetProxy->AddPhotoProxy((sptr<Media::PhotoProxy>&)photoProxyFuzzTest);

    int fd = FuzzInt32(data, size);
    photoAssetProxy->DealWithLowQualityPhoto(sDataShareHelper_, fd, FuzzString(data, size),
        (sptr<Media::PhotoProxy>&)photoProxyFuzzTest);
    photoAssetProxy->SaveLowQualityPhoto(sDataShareHelper_, (sptr<Media::PhotoProxy>&)photoProxyFuzzTest,
        FuzzInt32(data, size), FuzzPhotoSubType(data, size));
    photoAssetProxy->UpdatePhotoQuality(sDataShareHelper_, (sptr<Media::PhotoProxy>&)photoProxyFuzzTest,
        FuzzInt32(data, size), FuzzPhotoSubType(data, size));
    photoAssetProxy->LocationValueToString(FuzzDouble(data, size));
    photoAssetProxy->SetShootingModeAndGpsInfo(data, FuzzUInt32(data), (sptr<Media::PhotoProxy>&)photoProxyFuzzTest,
        FuzzInt32(data, size));
    photoAssetProxy->PackAndSaveImage(fd, FuzzString(data, size), (sptr<Media::PhotoProxy>&)photoProxyFuzzTest);
    photoAssetProxy->GetVideoFd();
    photoAssetProxy->NotifyVideoSaveFinished();
}

void SetTables()
{
    vector<string> createTableSqlList = {
        Media::PhotoColumn::CREATE_PHOTO_TABLE,
    };
    for (auto &createTableSql : createTableSqlList) {
        int32_t ret = g_rdbStore->ExecuteSql(createTableSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Execute sql %{private}s failed", createTableSql.c_str());
            return;
        }
        MEDIA_DEBUG_LOG("Execute sql %{private}s success", createTableSql.c_str());
    }
}

static void RdbStoreInit()
{
    auto stageContext = std::make_shared<AbilityRuntime::ContextImpl>();
    auto abilityContextImpl = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    abilityContextImpl->SetStageContext(stageContext);
    int32_t sceneCode = 0;
    auto ret = Media::MediaLibraryDataManager::GetInstance()->InitMediaLibraryMgr(abilityContextImpl,
        abilityContextImpl, sceneCode);
    CHECK_AND_RETURN_LOG(ret == NativeRdb::E_OK, "InitMediaLibraryMgr failed, ret: %{public}d", ret);

    auto rdbStore = Media::MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr || rdbStore->GetRaw() == nullptr) {
        return;
    }
    g_rdbStore = rdbStore->GetRaw();
    SetTables();
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::RdbStoreInit();
    OHOS::MediaLibraryMediaPhotoAssetProxyTest(data, size);
    return 0;
}