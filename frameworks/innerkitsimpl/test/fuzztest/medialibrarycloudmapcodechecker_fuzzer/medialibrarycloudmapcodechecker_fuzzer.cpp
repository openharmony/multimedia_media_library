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

#include "medialibrarycloudmapcodechecker_fuzzer.h"

#include <cstdint>
#include <string>

#define private public
#include "cloud_upload_checker.h"
#undef private
#include "ability_context_impl.h"
#include "media_log.h"
#include "medialibrary_command.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"

#include "map_code_upload_checker.h"
#include "photo_map_code_column.h"
#include "photo_map_code_operation.h"

namespace OHOS {
using namespace std;
using namespace AbilityRuntime;
static const string PHOTOS_TABLE = "Photos";
static const int32_t E_ERR = -1;
std::shared_ptr<Media::MediaLibraryRdbStore> g_rdbStore;
static inline int32_t FuzzInt32(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return 0;
    }
    return static_cast<int32_t>(*data);
}

static inline int64_t FuzzInt64(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return 0;
    }
    return static_cast<int64_t>(*data);
}

static inline string FuzzString(const uint8_t *data, size_t size)
{
    return {reinterpret_cast<const char*>(data), size};
}

static int32_t InsertPhotoAsset(const uint8_t *data, size_t size)
{
    if (g_rdbStore == nullptr || data == nullptr || size < sizeof(int32_t) + sizeof(int64_t)) {
        return E_ERR;
    }
    int offset = 0;
    NativeRdb::ValuesBucket values;
    values.PutString(Media::MediaColumn::MEDIA_FILE_PATH, FuzzString(data, size));
    values.PutInt(Media::PhotoColumn::PHOTO_DIRTY, FuzzInt32(data + offset, size));
    offset += sizeof(int64_t);
    values.PutLong(Media::MediaColumn::MEDIA_SIZE, FuzzInt64(data + offset, size));
    int64_t fileId = 0;
    g_rdbStore->Insert(fileId, PHOTOS_TABLE, values);
    return static_cast<int32_t>(fileId);
}

static Media::CheckedPhotoInfo FuzzCheckedPhotoInfo(const uint8_t *data, size_t size)
{
    Media::CheckedPhotoInfo checkedPhotoInfo = {
        .fileId = InsertPhotoAsset(data, size),
        .path = FuzzString(data, size)
    };
    return checkedPhotoInfo;
}

static vector<Media::CheckedPhotoInfo> FuzzVectorCheckedPhotoInfo(const uint8_t *data, size_t size)
{
    return {FuzzCheckedPhotoInfo(data, size)};
}

static void RepairNoOriginMapCodeTest(const uint8_t *data, size_t size)
{
    Media::CloudUploadChecker::QueryLcdPhotoCount(FuzzInt32(data, size));
    int32_t startFileId = InsertPhotoAsset(data, size);
    int32_t curFileId = -1;
    Media::CloudUploadChecker::QueryPhotoInfo(startFileId);
    Media::CloudUploadChecker::HandlePhotoInfos(FuzzVectorCheckedPhotoInfo(data, size), curFileId);
    Media::CloudUploadChecker::RepairNoOriginPhoto();
    
    Media::MapCodeUploadChecker::RepairNoMapCodePhoto();
}

static void CloudMapCodeCheckerTest(const uint8_t *data, size_t size)
{
    RepairNoOriginMapCodeTest(data, size);
}

void SetTables()
{
    vector<string> createTableSqlList = {
        Media::PhotoColumn::CREATE_PHOTO_TABLE,
        Media::PhotoMapCodeColumn::CREATE_MAP_CODE_TABLE,
        Media::PhotoAlbumColumns::CREATE_TABLE,
    };
    for (auto &createTableSql : createTableSqlList) {
        CHECK_AND_RETURN_LOG(g_rdbStore != nullptr, "g_rdbStore is null");
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
    int32_t sceneCode = 0;
    auto ret = Media::MediaLibraryDataManager::GetInstance()->InitMediaLibraryMgr(abilityContextImpl,
        abilityContextImpl, sceneCode);
    CHECK_AND_RETURN_LOG(ret == NativeRdb::E_OK, "InitMediaLibraryMgr failed, ret: %{public}d", ret);

    auto rdbStore = Media::MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return;
    }
    g_rdbStore = rdbStore;
    SetTables();
}
} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::Init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::CloudMapCodeCheckerTest(data, size);
    return 0;
}