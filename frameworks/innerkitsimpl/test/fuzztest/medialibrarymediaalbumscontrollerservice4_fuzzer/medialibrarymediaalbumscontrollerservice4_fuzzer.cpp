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

#include "medialibrarymediaalbumscontrollerservice4_fuzzer.h"
#include "medialibrary_rdbstore_utils_fuzzer.h"

#include <cstdint>
#include <string>
#include <fstream>
#include <fuzzer/FuzzedDataProvider.h>
#include "media_log.h"
#include "medialibrary_data_manager.h"
#include "media_albums_controller_service.h"
#include "change_request_set_display_level_vo.h"
#include "get_photo_album_object_vo.h"
#include "photo_album_column.h"

namespace OHOS::Media {
using namespace std;
static const int32_t NUM_BYTES = 8;
static const std::string TABLE = "PhotoAlbum";

FuzzedDataProvider* provider;
std::shared_ptr<Media::MediaLibraryRdbStore> g_rdbStore;

int32_t g_photoAlbumTypeArray[] = {
    -1, 0, 1024, 2048, 4096
};

int32_t g_photoAlbumSubTypeArray[] = {
    1, 1027, 2049, 2050, 4097
};

static inline int32_t FuzzPhotoAlbumType()
{
    return provider->PickValueInArray(g_photoAlbumTypeArray);
}

static inline int32_t FuzzPhotoAlbumSubType()
{
    return provider->PickValueInArray(g_photoAlbumSubTypeArray);
}

static int32_t InsertAlbumAsset()
{
    if (g_rdbStore == nullptr && provider == nullptr) {
        MEDIA_ERR_LOG("InsertAlbumAsset g_rdbStore or provider is null");
        return E_ERR;
    }

    NativeRdb::ValuesBucket values;
    values.PutInt(PhotoAlbumColumns::ALBUM_SUBTYPE, FuzzPhotoAlbumSubType());
    values.PutString(PhotoAlbumColumns::ALBUM_COVER_URI, provider->ConsumeBytesAsString(NUM_BYTES));
    int64_t fileId = 0;
    int32_t ret = g_rdbStore->Insert(fileId, TABLE, values);
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, E_ERR, "g_rdbStore failed to insert ret=%{public}d", ret);
    return static_cast<int32_t>(fileId);
}

static void ChangeRequestResetCoverUriFuzzer()
{
    MediaAlbumsControllerService service;
    ChangeRequestSetDisplayLevelReqBody reqBody;
    reqBody.albumId = to_string(provider->ConsumeIntegral<int32_t>());
    reqBody.albumType = FuzzPhotoAlbumType();
    reqBody.albumSubType = FuzzPhotoAlbumSubType();

    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    service.ChangeRequestResetCoverUri(data, reply);
}

static void GetPhotoAlbumObjectFuzzer()
{
    MediaAlbumsControllerService service;
    GetPhotoAlbumObjectReqBody reqBody;
    string whereClause = "GetPhotoAlbumObjectFuzzer";
    reqBody.predicates.SetWhereClause(whereClause);
    std::vector<std::string> whereArgs = {whereClause};
    reqBody.predicates.SetWhereArgs(whereArgs);
    reqBody.columns = {PhotoAlbumColumns::ALBUM_COUNT};

    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    service.GetPhotoAlbumObject(data, reply);
}

static void MediaAlbumsControllerService4Fuzzer()
{
    InsertAlbumAsset();
    ChangeRequestResetCoverUriFuzzer();
    GetPhotoAlbumObjectFuzzer();
}

void SetTables()
{
    vector<string> createTableSqlList = {
        PhotoAlbumColumns::CREATE_TABLE
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
} // namespace OHOS::Media

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::Media::Init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    CHECK_AND_RETURN_RET_LOG(data != nullptr, OHOS::Media::E_ERR, "data is nullptr");
    FuzzedDataProvider fdp(data, size);
    OHOS::Media::provider = &fdp;
    CHECK_AND_RETURN_RET_LOG(OHOS::Media::provider != nullptr, OHOS::Media::E_ERR, "provider is nullptr");

    OHOS::Media::MediaAlbumsControllerService4Fuzzer();
    return 0;
}