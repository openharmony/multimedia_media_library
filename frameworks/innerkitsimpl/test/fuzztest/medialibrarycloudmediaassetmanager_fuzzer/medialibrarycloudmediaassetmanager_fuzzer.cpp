/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "medialibrarycloudmediaassetmanager_fuzzer.h"
#include "medialibrary_rdbstore_utils_fuzzer.h"

#include <cstdint>
#include <string>
#include <fstream>
#include <pixel_map.h>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#include "cloud_media_asset_manager.h"
#include "cloud_media_asset_callback.h"
#include "cloud_media_asset_observer.h"
#include "cloud_media_asset_types.h"
#undef private
#include "ability_context_impl.h"
#include "media_log.h"
#include "medialibrary_command.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_type_const.h"
#include "medialibrary_unistore_manager.h"
#include "media_upgrade.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace AbilityRuntime;
using namespace FileManagement::CloudSync;
using Status = CloudMediaAssetDownloadOperation::Status;
static const int32_t MAX_CLOUD_MEDIA_DOWNLOAD_TYPE = 1;
static const int32_t MIN_CLOUD_MEDIA_TASK_RECOVER_CAUSE = 1;
static const int32_t MAX_URI_LIST = 5;
static const int32_t MAX_CLOUD_MEDIA_TASK_RECOVER_CAUSE = 7;
static const int32_t MAX_CLOUD_MEDIA_TASK_PAUSE_CAUSE = 9;
static const int32_t MAX_BYTE_VALUE = 256;
static const int32_t SEED_SIZE = 1024;
static const string PHOTOS_TABLE = "Photos";
std::shared_ptr<MediaLibraryRdbStore> g_rdbStore;
FuzzedDataProvider *provider = nullptr;

static inline CloudMediaDownloadType FuzzCloudMediaDownloadType()
{
    int32_t value = provider->ConsumeIntegralInRange<int32_t>(0, MAX_CLOUD_MEDIA_DOWNLOAD_TYPE);
    return static_cast<CloudMediaDownloadType>(value);
}

static inline CloudMediaTaskRecoverCause FuzzCloudMediaTaskRecoverCause()
{
    int32_t value = provider->ConsumeIntegralInRange<int32_t>(MIN_CLOUD_MEDIA_TASK_RECOVER_CAUSE,
        MAX_CLOUD_MEDIA_TASK_RECOVER_CAUSE);
    return static_cast<CloudMediaTaskRecoverCause>(value);
}

static inline CloudMediaTaskPauseCause FuzzCloudMediaTaskPauseCause()
{
    int32_t value = provider->ConsumeIntegralInRange<int32_t>(0, MAX_CLOUD_MEDIA_TASK_PAUSE_CAUSE);
    return static_cast<CloudMediaTaskPauseCause>(value);
}

static inline Uri FuzzUri()
{
    int32_t data = provider->ConsumeIntegralInRange<int32_t>(0, MAX_URI_LIST);
    string uriStr = CLOUD_MEDIA_ASSET_MANAGER_FUZZER_URI_LISTS[data];
    Uri uri(uriStr);
    return uri;
}

static inline MediaLibraryCommand FuzzMediaLibraryCmd()
{
    return MediaLibraryCommand(FuzzUri());
}

void SetTables()
{
    vector<string> createTableSqlList = { PhotoUpgrade::CREATE_PHOTO_TABLE };
    for (auto &createTableSql : createTableSqlList) {
        CHECK_AND_RETURN_LOG(g_rdbStore != nullptr, "g_rdbStore is null.");
        int32_t ret = g_rdbStore->ExecuteSql(createTableSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Execute sql %{private}s failed", createTableSql.c_str());
            return;
        }
        MEDIA_DEBUG_LOG("Execute sql %{private}s success", createTableSql.c_str());
    }
}

static void Init()
{
    auto stageContext = std::make_shared<AbilityRuntime::ContextImpl>();
    auto abilityContextImpl = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    abilityContextImpl->SetStageContext(stageContext);
    auto rdbStore = Media::MediaLibraryRdbStoreUtilsTest::InitMediaLibraryRdbStore(abilityContextImpl);
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return;
    }
    g_rdbStore = rdbStore;
    SetTables();
}

static void CloudMediaAssetManagerFuzzer()
{
    MediaLibraryCommand cmd = FuzzMediaLibraryCmd();
    CloudMediaAssetManager::GetInstance().HandleCloudMediaAssetUpdateOperations(cmd);
    CloudMediaAssetManager::GetInstance().HandleCloudMediaAssetGetTypeOperations(cmd);
}

static void CloudMediaAssetDownloadFuzzer()
{
    CloudMediaAssetManager &instance =  CloudMediaAssetManager::GetInstance();
    int32_t value = provider->ConsumeIntegral<int32_t>();
    instance.CheckDownloadTypeOfTask(static_cast<CloudMediaDownloadType>(value));

    instance.StartDownloadCloudAsset(static_cast<CloudMediaDownloadType>(value));
    instance.StartDownloadCloudAsset(FuzzCloudMediaDownloadType());
    instance.RecoverDownloadCloudAsset(FuzzCloudMediaTaskRecoverCause());
    instance.PauseDownloadCloudAsset(FuzzCloudMediaTaskPauseCause());
    instance.CancelDownloadCloudAsset();
    instance.GetCloudMediaAssetTaskStatus();
    instance.SetIsThumbnailUpdate();
    instance.GetTaskStatus();
    instance.GetDownloadType();
    instance.SetBgDownloadPermission(provider->ConsumeBool());
    instance.CheckStorageAndRecoverDownloadTask();
}

static int32_t AddSeed()
{
    char *seedData = new char[OHOS::Media::SEED_SIZE];
    for (int i = 0; i < OHOS::Media::SEED_SIZE; i++) {
        seedData[i] = static_cast<char>(i % MAX_BYTE_VALUE);
    }

    const char* filename = "corpus/seed.txt";
    std::ofstream file(filename, std::ios::binary | std::ios::trunc);
    if (!file) {
        MEDIA_ERR_LOG("Cannot open file filename:%{public}s", filename);
        delete[] seedData;
        return Media::E_ERR;
    }
    file.write(seedData, OHOS::Media::SEED_SIZE);
    file.close();
    delete[] seedData;
    MEDIA_INFO_LOG("seedData has been successfully written to file filename:%{public}s", filename);
    return Media::E_OK;
}
} // namespace Media
} // namespace OHOS
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::Media::AddSeed();
    OHOS::Media::Init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::Media::provider = &fdp;
    if (data == nullptr) {
        return 0;
    }
    OHOS::Media::CloudMediaAssetManagerFuzzer();
    OHOS::Media::CloudMediaAssetDownloadFuzzer();
    return 0;
}