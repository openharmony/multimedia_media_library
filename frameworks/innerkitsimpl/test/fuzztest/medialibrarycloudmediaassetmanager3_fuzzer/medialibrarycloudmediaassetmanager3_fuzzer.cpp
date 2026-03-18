/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "medialibrarycloudmediaassetmanager3_fuzzer.h"
#include "medialibrary_rdbstore_utils_fuzzer.h"

#include <cstdint>
#include <string>
#include <fstream>
#include <pixel_map.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "cloud_media_asset_manager.h"
#include "media_log.h"
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
static const int32_t MAX_URI_LIST = 5;
static const int32_t MAX_BYTE_VALUE = 256;
static const int32_t SEED_SIZE = 1024;
std::shared_ptr<MediaLibraryRdbStore> g_rdbStore;
FuzzedDataProvider *provider = nullptr;

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
    if (data == nullptr) {
        return 0;
    }
    FuzzedDataProvider fdp(data, size);
    OHOS::Media::provider = &fdp;
    OHOS::Media::CloudMediaAssetManagerFuzzer();
    return 0;
}