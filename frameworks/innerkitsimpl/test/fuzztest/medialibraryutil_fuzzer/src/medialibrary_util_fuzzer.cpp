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
#include <thread>

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
#include "multistages_capture_dfx_first_visit.h"
#include "rdb_predicates.h"
#include "datashare_values_bucket.h"
#include "media_analysis_proxy.h"
#include "media_analysis_helper.h"
#include "background_cloud_file_processor.h"
#include "medialibrary_db_const.h"
#include "medialibrary_album_refresh.h"

namespace OHOS {
using namespace std;

static inline string FuzzString(const uint8_t *data, size_t size)
{
    return {reinterpret_cast<const char*>(data), size};
}

static inline int32_t FuzzInt32(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return 0;
    }
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
    const int32_t int32Count = 10;
    if (data == nullptr || size < sizeof(int32_t) * int32Count) {
        return;
    }
    NativeRdb::ValuesBucket value;
    int32_t offset = 0;
    int32_t operationObject1 = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t operationType1 = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t mediaLibraryApi1 = FuzzInt32(data + offset, size);
    Media::MediaLibraryCommand cmd(static_cast<Media::OperationObject>(operationObject1),
        static_cast<Media::OperationType>(operationType1), static_cast<Media::MediaLibraryApi>(mediaLibraryApi1));
    cmd.SetTableName(FuzzString(data, size));
    cmd.SetBundleName(FuzzString(data, size));
    cmd.SetDeviceName(FuzzString(data, size));
    cmd.SetResult(FuzzString(data, size));
    offset += sizeof(int32_t);
    int32_t operationObject2 = FuzzInt32(data + offset, size);
    cmd.SetOprnObject(static_cast<Media::OperationObject>(operationObject2));
    cmd.GetOprnFileId();
    cmd.SetOprnAssetId(FuzzString(data, size));
    DataShare::DataSharePredicates pred;
    cmd.SetDataSharePred(pred);
    cmd.SetValueBucket(value);
    Media::MediaLibraryCommand cmdValueBucket(FuzzUri(data, size), value);
    offset += sizeof(int32_t);
    int32_t operationObject3 = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t operationType2 = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t mediaLibraryApi2 = FuzzInt32(data + offset, size);
    Media::MediaLibraryCommand cmdValueBucket2(static_cast<Media::OperationObject>(operationObject3),
        static_cast<Media::OperationType>(operationType2), value,
        static_cast<Media::MediaLibraryApi>(mediaLibraryApi2));
    offset += sizeof(int32_t);
    int32_t operationObject4 = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t operationType3 = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t mediaLibraryApi3 = FuzzInt32(data + offset, size);
    Media::MediaLibraryCommand cmdDevice(static_cast<Media::OperationObject>(operationObject4),
        static_cast<Media::OperationType>(operationType3), FuzzString(data, size),
        static_cast<Media::MediaLibraryApi>(mediaLibraryApi3));
}

static void DirOperationTest(const uint8_t *data, size_t size)
{
    const int32_t int32Count = 2;
    if (data == nullptr || size < sizeof(int32_t) * int32Count) {
        return;
    }
    int32_t offset = 0;
    int32_t operationObject = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t operationType = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t mediaLibraryApi = FuzzInt32(data + offset, size);
    Media::MediaLibraryCommand cmd(static_cast<Media::OperationObject>(operationObject),
        static_cast<Media::OperationType>(operationType), static_cast<Media::MediaLibraryApi>(mediaLibraryApi));
    Media::MediaLibraryDirOperations::HandleDirOperation(cmd);
    Media::MediaLibraryDirOperations::CreateDirOperation(cmd);
    Media::MediaLibraryDirOperations::TrashDirOperation(cmd);
}

static void UriPermissionTest(const uint8_t *data, size_t size)
{
    const int32_t int32Count = 6;
    if (data == nullptr || size < sizeof(int32_t) * int32Count) {
        return;
    }
    int32_t offset = 0;
    int32_t operationObject = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t operationType = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t mediaLibraryApi = FuzzInt32(data + offset, size);
    Media::MediaLibraryCommand cmd(static_cast<Media::OperationObject>(operationObject),
        static_cast<Media::OperationType>(operationType), static_cast<Media::MediaLibraryApi>(mediaLibraryApi));
    NativeRdb::ValuesBucket rdbValueBucket;
    offset += sizeof(int32_t);
    rdbValueBucket.Put(Media::PERMISSION_FILE_ID, FuzzInt32(data + offset, size));
    rdbValueBucket.Put(Media::PERMISSION_BUNDLE_NAME, FuzzString(data, size));
    rdbValueBucket.Put(Media::PERMISSION_MODE, "r");
    rdbValueBucket.Put(Media::PERMISSION_TABLE_TYPE, FuzzString(data, size));
    cmd.SetValueBucket(rdbValueBucket);
    Media::UriPermissionOperations::HandleUriPermOperations(cmd);
    Media::UriPermissionOperations::HandleUriPermInsert(cmd);
    offset += sizeof(int32_t);
    Media::UriPermissionOperations::InsertBundlePermission(FuzzInt32(data + offset, size), FuzzString(data, size),
        FuzzString(data, size), FuzzString(data, size));
    Media::UriPermissionOperations::DeleteBundlePermission(FuzzString(data, size),
        FuzzString(data, size), FuzzString(data, size));
    string mode = "r";
    Media::UriPermissionOperations::CheckUriPermission(FuzzString(data, size), mode);

    offset += sizeof(int32_t);
    Media::UriPermissionOperations::GetUriPermissionMode(FuzzString(data, size), FuzzString(data, size),
        FuzzInt32(data + offset, size), mode);
    Media::UriPermissionOperations::UpdateOperation(cmd);
    Media::UriPermissionOperations::InsertOperation(cmd);
    std::vector<NativeRdb::ValuesBucket> rdbValues;
    Media::UriPermissionOperations::BatchInsertOperation(cmd, rdbValues);
    Media::UriPermissionOperations::DeleteOperation(cmd);
    std::vector<DataShare::DataShareValuesBucket> sharedValues;
    DataShare::DataShareValuesBucket valueTest1;
    valueTest1.Put(Media::AppUriPermissionColumn::FILE_ID, "file_id");
    valueTest1.Put(Media::AppUriPermissionColumn::APP_ID, "appid");
    DataShare::DataShareValuesBucket valueTest2;
    valueTest2.Put(Media::AppUriPermissionColumn::FILE_ID, "file_id");
    valueTest2.Put(Media::AppUriPermissionColumn::APP_ID, "appid");
    sharedValues.push_back(valueTest1);
    sharedValues.push_back(valueTest2);
    Media::UriPermissionOperations::GrantUriPermission(cmd, sharedValues);
    Media::UriPermissionOperations::DeleteAllTemporaryAsync();
}

static void AnalysisTest(const uint8_t *data, size_t size)
{
    const int32_t int32Count = 7;
    if (data == nullptr || size < sizeof(int32_t) * int32Count) {
        return;
    }
    std::vector<std::string> columns;
    NativeRdb::ValuesBucket values;
    DataShare::DataSharePredicates pred;
    int32_t offset = 0;
    int32_t operationObject = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t operationType = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t mediaLibraryApi = FuzzInt32(data + offset, size);
    Media::MediaLibraryCommand cmd(static_cast<Media::OperationObject>(operationObject),
        static_cast<Media::OperationType>(operationType), static_cast<Media::MediaLibraryApi>(mediaLibraryApi));
    cmd.SetTableName("Photos");
    Media::MergeAlbumInfo info1;
    offset += sizeof(int32_t);
    info1.albumId = FuzzInt32(data + offset, size);
    Media::MergeAlbumInfo info2;
    offset += sizeof(int32_t);
    info2.albumId = FuzzInt32(data + offset, size);
    std::vector<Media::MergeAlbumInfo> infos;
    infos.push_back(info1);
    infos.push_back(info2);
    Media::MediaLibraryAnalysisAlbumOperations::UpdateMergeGroupAlbumsInfo(infos);
    offset += sizeof(int32_t);
    Media::MediaLibraryAnalysisAlbumOperations::HandleGroupPhotoAlbum(
        static_cast<Media::OperationType>(FuzzInt32(data + offset, size)), values, pred);
    Media::MediaLibraryAnalysisAlbumOperations::QueryGroupPhotoAlbum(cmd, columns);
    offset += sizeof(int32_t);
    Media::MediaLibraryAnalysisAlbumOperations::UpdateGroupPhotoAlbumById(FuzzInt32(data + offset, size));
}

static void AppPermissionTest(const uint8_t *data, size_t size)
{
    const int32_t int32Count = 3;
    if (data == nullptr || size < sizeof(int32_t) * int32Count) {
        return;
    }
    std::vector<std::string> columns;
    NativeRdb::RdbPredicates rdbPred("Photos");
    DataShare::DataSharePredicates sharedPred;
    int32_t offset = 0;
    int32_t operationObject = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t operationType = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t mediaLibraryApi = FuzzInt32(data + offset, size);
    Media::MediaLibraryCommand cmd(static_cast<Media::OperationObject>(operationObject),
        static_cast<Media::OperationType>(operationType), static_cast<Media::MediaLibraryApi>(mediaLibraryApi));
    Media::MediaLibraryAppUriPermissionOperations::HandleInsertOperation(cmd);
    std::vector<DataShare::DataShareValuesBucket> sharedValues;
    DataShare::DataShareValuesBucket values;
    values.Put(Media::AppUriPermissionColumn::FILE_ID, "file_id");
    values.Put(Media::AppUriPermissionColumn::APP_ID, "appid");
    sharedValues.push_back(values);
    Media::MediaLibraryAppUriPermissionOperations::BatchInsert(cmd, sharedValues);
    Media::MediaLibraryAppUriPermissionOperations::DeleteOperation(rdbPred);
    Media::MediaLibraryAppUriPermissionOperations::QueryOperation(sharedPred, columns);
}

static void AppStateTest()
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

static void MultistageTest(const uint8_t *data, size_t size)
{
    Media::MultiStagesCaptureDfxFirstVisit::GetInstance().Report(FuzzString(data, size));
}

static void RefreshAlbumTest()
{
    Media::RefreshAlbums(true);
}

static void ActiveAnalysisTest()
{
    std::vector<std::string> fileIds;
    fileIds.push_back("1");
    Media::MediaAnalysisHelper::StartMediaAnalysisServiceSync(
        static_cast<int32_t>(Media::MediaAnalysisProxy::ActivateServiceType::START_SERVICE_OCR), fileIds);
    Media::MediaAnalysisHelper::StartMediaAnalysisServiceAsync(
        static_cast<int32_t>(Media::MediaAnalysisProxy::ActivateServiceType::START_SERVICE_OCR), fileIds);
}

static void CloudDownloadTest()
{
    Media::BackgroundCloudFileProcessor::StartTimer();
    int sleepTime = 200;
    std::this_thread::sleep_for(std::chrono::microseconds(sleepTime));
    Media::BackgroundCloudFileProcessor::StopTimer();
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
    int sleepTime = 100;
    std::this_thread::sleep_for(std::chrono::microseconds(sleepTime));
    OHOS::CommandTest(data, size);
    OHOS::DirOperationTest(data, size);
    OHOS::UriPermissionTest(data, size);
    OHOS::AnalysisTest(data, size);
    OHOS::AppPermissionTest(data, size);
    OHOS::AppStateTest();
    OHOS::MediaLibraryManagerTest(data, size);
    OHOS::MultistageTest(data, size);
    OHOS::RefreshAlbumTest();
    OHOS::ActiveAnalysisTest();
    OHOS::CloudDownloadTest();
    return 0;
}
