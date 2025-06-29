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
#include <fuzzer/FuzzedDataProvider.h>

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
static const int32_t MAX_PHOTO_QUALITY_FUZZER_LISTS = 1;
static const int32_t MAX_CAMERA_SHOT_TYPE_FUZZER_LISTS = 3;
static const int32_t MAX_PHOTO_FORMAT_FUZZER_LISTS = 3;
constexpr int FUZZ_STORAGE_MANAGER_MANAGER_ID = 5003;
std::shared_ptr<DataShare::DataShareHelper> sDataShareHelper_ = nullptr;
std::shared_ptr<Media::MediaLibraryRdbStore> g_rdbStore;
FuzzedDataProvider *provider = nullptr;

static inline Media::CameraShotType FuzzCameraShotType()
{
    uint8_t data = provider->ConsumeIntegralInRange<uint8_t>(0, MAX_CAMERA_SHOT_TYPE_FUZZER_LISTS);
    return Media::CameraShotType_FUZZER_LISTS[data];
}

static inline Media::PhotoFormat FuzzPhotoFormat()
{
    uint8_t data = provider->ConsumeIntegralInRange<uint8_t>(0, MAX_PHOTO_FORMAT_FUZZER_LISTS);
    return Media::PhotoFormat_FUZZER_LISTS[data];
}

static inline Media::PhotoQuality FuzzPhotoQuality()
{
    uint8_t data = provider->ConsumeIntegralInRange<uint8_t>(0, MAX_PHOTO_QUALITY_FUZZER_LISTS);
    return Media::PhotoQuality_FUZZER_LISTS[data];
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

static shared_ptr<Media::PhotoAssetProxy> Init()
{
    shared_ptr<Media::PhotoAssetProxy> photoAssetProxy = make_shared<Media::PhotoAssetProxy>(sDataShareHelper_,
        FuzzCameraShotType(), provider->ConsumeIntegral<int32_t>(), provider->ConsumeIntegral<int32_t>());
    return photoAssetProxy;
}

static sptr<Media::PhotoProxyFuzzTest> FuzzPhotoAssetProxy()
{
    sptr<Media::PhotoProxyFuzzTest> photoProxyFuzzTest = new(std::nothrow) Media::PhotoProxyFuzzTest();
    if (photoProxyFuzzTest == nullptr) {
        return nullptr;
    }
    photoProxyFuzzTest->SetFormat(FuzzPhotoFormat());
    photoProxyFuzzTest->SetPhotoQuality(FuzzPhotoQuality());

    return photoProxyFuzzTest;
}

static void MediaLibraryMediaPhotoAssetProxyTest()
{
    if (sDataShareHelper_ == nullptr) {
        CreateDataHelper(FUZZ_STORAGE_MANAGER_MANAGER_ID);
    }
    shared_ptr<Media::PhotoAssetProxy> photoAssetProxy = Init();
    if (photoAssetProxy == nullptr) {
        return;
    }
    sptr<Media::PhotoProxyFuzzTest> photoProxyFuzzTest = FuzzPhotoAssetProxy();
    photoAssetProxy->AddPhotoProxy((sptr<Media::PhotoProxy>&)photoProxyFuzzTest);
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

    auto rdbStore = Media::MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        return;
    }
    g_rdbStore = rdbStore;
    SetTables();
}
} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::RdbStoreInit();
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    OHOS::provider = &fdp;
    if (data == nullptr) {
        return 0;
    }
    OHOS::MediaLibraryMediaPhotoAssetProxyTest();
    return 0;
}