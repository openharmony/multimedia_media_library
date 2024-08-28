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
#include "medialibrary_util_fuzzer.h"

#include <cstdint>
#include <string>

#include "ability_context_impl.h"
#include "app_mgr_interface.h"
#include "medialibrary_album_operations.h"
#include "medialibrary_analysis_album_operations.h"
#include "medialibrary_app_uri_permission_operations.h"
#include "medialibrary_appstate_observer.h"
#include "media_log.h"
#include "medialibrary_command.h"
#include "medialibrary_dir_operations.h"
#include "medialibrary_uripermission_operations.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_data_manager_utils.h"
#include "rdb_predicates.h"
#include "datashare_values_bucket.h"

namespace OHOS {
using namespace std;

static inline string FuzzString(const uint8_t *data, size_t size)
{
    return {reinterpret_cast<const char*>(data), size};
}

static inline int32_t FuzzInt32(const uint8_t *data)
{
    return static_cast<int32_t>(*data);
}

static inline Uri FuzzUri(const uint8_t *data, size_t size)
{
    return Uri(FuzzString(data, size));
}

static int Init()
{
    auto stageContext = std::make_shared<AbilityRuntime::ContextImpl>();
    auto abilityContextImpl = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    abilityContextImpl->SetStageContext(stageContext);
    int32_t sceneCode = 0;
    return Media::MediaLibraryDataManager::GetInstance()->InitMediaLibraryMgr(abilityContextImpl, abilityContextImpl,
        sceneCode);
}

static void CommandTest(const uint8_t *data, size_t size)
{
    NativeRdb::ValuesBucket value;
    Media::MediaLibraryCommand cmd(static_cast<Media::OperationObject>(FuzzInt32(data)),
        static_cast<Media::OperationType>(FuzzInt32(data)), static_cast<Media::MediaLibraryApi>(FuzzInt32(data)));
    cmd.SetTableName(FuzzString(data, size));
    cmd.SetBundleName(FuzzString(data, size));
    cmd.SetDeviceName(FuzzString(data, size));
    cmd.SetResult(FuzzString(data, size));
    cmd.SetOprnAssetId(FuzzString(data, size));
    cmd.SetOprnObject(static_cast<Media::OperationObject>(FuzzInt32(data)));
    cmd.GetOprnFileId();
    DataShare::DataSharePredicates pred;
    cmd.SetDataSharePred(pred);
    cmd.SetValueBucket(value);
    Media::MediaLibraryCommand cmdValueBucket(FuzzUri(data, size), value);
    Media::MediaLibraryCommand cmdValueBucket2(static_cast<Media::OperationObject>(FuzzInt32(data)),
        static_cast<Media::OperationType>(FuzzInt32(data)), value,
        static_cast<Media::MediaLibraryApi>(FuzzInt32(data)));
    Media::MediaLibraryCommand cmdDevice(static_cast<Media::OperationObject>(FuzzInt32(data)),
        static_cast<Media::OperationType>(FuzzInt32(data)), FuzzString(data, size),
        static_cast<Media::MediaLibraryApi>(FuzzInt32(data)));
}

static void DirOperationTest(const uint8_t *data, size_t size)
{
    Media::MediaLibraryCommand cmd(static_cast<Media::OperationObject>(FuzzInt32(data)),
        static_cast<Media::OperationType>(FuzzInt32(data)), static_cast<Media::MediaLibraryApi>(FuzzInt32(data)));
    Media::MediaLibraryDirOperations::HandleDirOperation(cmd);
    Media::MediaLibraryDirOperations::CreateDirOperation(cmd);
    Media::MediaLibraryDirOperations::TrashDirOperation(cmd);
}

static void UriPermissionTest(const uint8_t *data, size_t size)
{
    Media::MediaLibraryCommand cmd(static_cast<Media::OperationObject>(FuzzInt32(data)),
        static_cast<Media::OperationType>(FuzzInt32(data)), static_cast<Media::MediaLibraryApi>(FuzzInt32(data)));
    Media::UriPermissionOperations::HandleUriPermOperations(cmd);
    Media::UriPermissionOperations::HandleUriPermInsert(cmd);
    Media::UriPermissionOperations::InsertBundlePermission(FuzzInt32(data), FuzzString(data, size),
        FuzzString(data, size), FuzzString(data, size));
    Media::UriPermissionOperations::DeleteBundlePermission(FuzzString(data, size),
        FuzzString(data, size), FuzzString(data, size));
    string mode = "r";
    Media::UriPermissionOperations::CheckUriPermission(FuzzString(data, size), mode);
}

static void AnalysisTest(const uint8_t *data, size_t size)
{
    std::vector<std::string> columns;
    NativeRdb::ValuesBucket values;
    DataShare::DataSharePredicates pred;
    Media::MediaLibraryCommand cmd(static_cast<Media::OperationObject>(FuzzInt32(data)),
        static_cast<Media::OperationType>(FuzzInt32(data)), static_cast<Media::MediaLibraryApi>(FuzzInt32(data)));
    Media::MergeAlbumInfo info;
    info.albumId = FuzzInt32(data);
    std::vector<Media::MergeAlbumInfo> infos;
    infos.push_back(info);
    Media::MediaLibraryAnalysisAlbumOperations::UpdateMergeGroupAlbumsInfo(infos);
    Media::MediaLibraryAnalysisAlbumOperations::HandleGroupPhotoAlbum(
        static_cast<Media::OperationType>(FuzzInt32(data)), values, pred);
    Media::MediaLibraryAnalysisAlbumOperations::QueryGroupPhotoAlbum(cmd, columns);
    Media::MediaLibraryAnalysisAlbumOperations::UpdateGroupPhotoAlbumById(FuzzInt32(data));
}

static void AppPermissionTest(const uint8_t *data, size_t size)
{
    std::vector<std::string> columns;
    NativeRdb::RdbPredicates rdbPred("Photos");
    DataShare::DataSharePredicates sharedPred;

    Media::MediaLibraryCommand cmd(static_cast<Media::OperationObject>(FuzzInt32(data)),
        static_cast<Media::OperationType>(FuzzInt32(data)), static_cast<Media::MediaLibraryApi>(FuzzInt32(data)));
    Media::MediaLibraryAppUriPermissionOperations::HandleInsertOperation(cmd);
    std::vector<DataShare::DataShareValuesBucket> sharedValues;
    Media::MediaLibraryAppUriPermissionOperations::BatchInsert(cmd, sharedValues);
    Media::MediaLibraryAppUriPermissionOperations::DeleteOperation(rdbPred);
    Media::MediaLibraryAppUriPermissionOperations::QueryOperation(sharedPred, columns);
}

static void AppStateTest(const uint8_t *data, size_t size)
{
    Media::MedialibraryAppStateObserverManager::GetInstance().SubscribeAppState();
    Media::MedialibraryAppStateObserverManager::GetInstance().UnSubscribeAppState();
}

static void MediaLibraryManagerTest(const uint8_t *data, size_t size)
{
    Media::MediaLibraryDataManagerUtils::IsNumber(FuzzString(data, size));
    Media::MediaLibraryDataManagerUtils::GetOperationType(FuzzString(data, size));
    Media::MediaLibraryDataManagerUtils::GetDisPlayNameFromPath(FuzzString(data, size));
    std::vector<std::string> whereArgs;
    std::string str = FuzzString(data, size);
    Media::MediaLibraryDataManagerUtils::ObtionCondition(str, whereArgs);
    Media::MediaLibraryDataManagerUtils::GetTypeUriByUri(str);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::Init();
    OHOS::CommandTest(data, size);
    OHOS::DirOperationTest(data, size);
    OHOS::UriPermissionTest(data, size);
    OHOS::AnalysisTest(data, size);
    OHOS::AppPermissionTest(data, size);
    OHOS::AppStateTest(data, size);
    OHOS::MediaLibraryManagerTest(data, size);
    return 0;
}
