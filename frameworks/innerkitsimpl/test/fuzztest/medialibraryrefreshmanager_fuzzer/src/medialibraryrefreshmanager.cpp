/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "medialibraryrefreshmanager.h"

#include "medialibrary_errno.h"
#include "medialibrary_type_const.h"
#include "medialibrary_tracer.h"
#include "media_log.h"
#include "result_set_utils.h"
#include "media_file_utils.h"
#include "media_file_uri.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_rdb_transaction.h"
#include "medialibrary_notify.h"
#include "userfilemgr_uri.h"
#include "media_refresh_album_column.h"
#include "albums_refresh_worker.h"
#include "albums_refresh_notify.h"
#include "rdb_sql_utils.h"
#include "result_set_utils.h"
#include "photo_album_column.h"
#include "medialibrary_rdb_utils.h"
#include "vision_column.h"
#include "medialibrary_restore.h"
#include "post_event_utils.h"
#ifdef HAS_POWER_MANAGER_PART
#include "power_mgr_client.h"
#endif

namespace OHOS {
using namespace std;
using namespace DataShare;
using namespace DistributedKv;
using namespace NativeRdb;
using namespace AAFwk;
using ChangeType = DataShare::DataShareObserver::ChangeType;

static inline string FuzzString(const uint8_t *data, size_t size)
{
    return {reinterpret_cast<const char*>(data), size};
}

static inline int8_t FuzzInt8(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int8_t)) {
        return 0;
    }
    return static_cast<int8_t>(*data);
}

static inline int16_t FuzzInt16(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int16_t)) {
        return 0;
    }
    return static_cast<int16_t>(*data);
}

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

static inline bool FuzzBool(const uint8_t* data, size_t size)
{
    if (size == 0) {
        return false;
    }
    return (data[0] % EVEN) == 0;
}

static inline Uri FuzzUri(const uint8_t* data, size_t size)
{
    return Uri(FuzzString(data, size));
}

static inline std::list<Uri> FuzzListUri(const uint8_t* data, size_t size)
{
    return std::list<FuzzListUri(data, size)>;
}

static inline std::unordered_set<std::string> FuzzUnorderedSet(const uint8_t* data, size_t size)
{
    return std::unordered_set<FuzzString(data, size)>;
}

static Media::SyncNotifyInfo FuzzSyncNotifyInfo(const uint8_t* data, size_t size)
{
    Media::SyncNotifyInfo info = {
        .taskType = FuzzInt16(data, size);
        .syncType = FuzzInt16(data, size);
        .notifyType = Media::NotifyType::NOTIFY_ADD;
        .syncId = FuzzString(data, size);
        .totalAssets = FuzzInt32(data, size);
        .totalAlbums = FuzzInt32(data, size);
        .uriType = FuzzInt8(data, size);
        .reserve = FuzzInt8(data, size);
        .urisSize  = FuzzInt16(data, size);
        .uris = FuzzListUri(data, size);
        .extraUris = FuzzListUri(data, size);
        .uriIds = FuzzUnorderedSet(data, size);
        .notifyAssets = FuzzBool(data, size);
        .notifyAlbums = FuzzBool(data, size);
        .refreshResult = FuzzInt32(data, size);
        .forceRefreshType = ForceRefreshType::NONE;
    }
    return info;
}

static void RefreshNotifyInfoTest(const uint8_t* data, size_t size)
{
    Media::SyncNotifyInfo fuzzinfo = FuzzSyncNotifyInfo(const uint8_t* data, size_t size);
    RefreshPhotoAlbums(fuzzinfo);
    AddAlbumRefreshTask(fuzzinfo);
    NotifyPhotoAlbums(fuzzinfo);
    HasRefreshingSystemAlbums();
}

} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::Init();
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::RefreshNotifyInfoTest(data, size);
    return 0;
}