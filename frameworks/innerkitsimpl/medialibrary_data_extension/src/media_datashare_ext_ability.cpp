/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#define MLOG_TAG "Extension"

#include "media_datashare_ext_ability.h"

#include <cstdlib>

#include "ability_info.h"
#include "app_mgr_client.h"
#include "dataobs_mgr_client.h"
#include "datashare_ext_ability_context.h"
#include "hilog_wrapper.h"
#include "ipc_skeleton.h"
#include "medialibrary_command.h"
#include "media_datashare_stub_impl.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "media_scanner_manager.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_bundle_manager.h"
#include "dfx_manager.h"
#include "dfx_timer.h"
#include "dfx_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_object_utils.h"
#include "medialibrary_subscriber.h"
#include "medialibrary_uripermission_operations.h"
#include "multistages_capture_manager.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "permission_utils.h"
#include "photo_album_column.h"
#include "runtime.h"
#include "singleton.h"
#include "system_ability_definition.h"
#include "uri_permission_manager_client.h"
#include "want.h"
#ifdef MEDIALIBRARY_SECURITY_OPEN
#include "sec_comp_kit.h"
#endif
#include "userfilemgr_uri.h"
#include "parameters.h"

using namespace std;
using namespace OHOS::AppExecFwk;
using namespace OHOS::NativeRdb;
using namespace OHOS::DistributedKv;
using namespace OHOS::Media;
using namespace OHOS::DataShare;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;
using DataObsMgrClient = OHOS::AAFwk::DataObsMgrClient;

const string secuityComponentMode = "rw";

MediaDataShareExtAbility* MediaDataShareExtAbility::Create(const unique_ptr<Runtime>& runtime)
{
    return new MediaDataShareExtAbility(static_cast<Runtime&>(*runtime));
}

MediaDataShareExtAbility::MediaDataShareExtAbility(Runtime& runtime) : DataShareExtAbility(), runtime_(runtime) {}

MediaDataShareExtAbility::~MediaDataShareExtAbility()
{
}

void MediaDataShareExtAbility::Init(const shared_ptr<AbilityLocalRecord> &record,
    const shared_ptr<OHOSApplication> &application, shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    if ((record == nullptr) || (application == nullptr) || (handler == nullptr) || (token == nullptr)) {
        MEDIA_ERR_LOG("MediaDataShareExtAbility::init failed, some object is nullptr");
        DelayedSingleton<AppExecFwk::AppMgrClient>::GetInstance()->KillApplicationSelf();
        return;
    }
    DataShareExtAbility::Init(record, application, handler, token);
}

void MediaDataShareExtAbility::OnStart(const AAFwk::Want &want)
{
    MEDIA_INFO_LOG("%{public}s begin.", __func__);
    Extension::OnStart(want);
    auto context = AbilityRuntime::Context::GetApplicationContext();
    if (context == nullptr) {
        MEDIA_ERR_LOG("Failed to get context");
        DelayedSingleton<AppExecFwk::AppMgrClient>::GetInstance()->KillApplicationSelf();
        return;
    }
    MEDIA_INFO_LOG("%{public}s runtime language  %{public}d", __func__, runtime_.GetLanguage());

    auto dataManager = MediaLibraryDataManager::GetInstance();
    if (dataManager == nullptr) {
        MEDIA_ERR_LOG("Failed to get dataManager");
        DelayedSingleton<AppExecFwk::AppMgrClient>::GetInstance()->KillApplicationSelf();
        return;
    }
    auto extensionContext = GetContext();
    int32_t ret = dataManager->InitMediaLibraryMgr(context, extensionContext);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("Failed to init MediaLibraryMgr");
        DelayedSingleton<AppExecFwk::AppMgrClient>::GetInstance()->KillApplicationSelf();
        return;
    }
    dataManager->SetOwner(static_pointer_cast<MediaDataShareExtAbility>(shared_from_this()));

    DfxManager::GetInstance();
    auto scannerManager = MediaScannerManager::GetInstance();
    if (scannerManager != nullptr) {
        scannerManager->Start();
    } else {
        MEDIA_ERR_LOG("Failed to get scanner manager");
        DelayedSingleton<AppExecFwk::AppMgrClient>::GetInstance()->KillApplicationSelf();
        return;
    }

    MultiStagesCaptureManager::GetInstance().Init();

    Media::MedialibrarySubscriber::Subscribe();
    dataManager->SetStartupParameter();
    MEDIA_INFO_LOG("%{public}s end.", __func__);
}

void MediaDataShareExtAbility::OnStop()
{
    MEDIA_INFO_LOG("%{public}s begin.", __func__);
    auto scannerManager = MediaScannerManager::GetInstance();
    if (scannerManager != nullptr) {
        scannerManager->Stop();
    }
    MediaLibraryDataManager::GetInstance()->ClearMediaLibraryMgr();
    MEDIA_INFO_LOG("%{public}s end.", __func__);
}

sptr<IRemoteObject> MediaDataShareExtAbility::OnConnect(const AAFwk::Want &want)
{
    MEDIA_INFO_LOG("%{public}s begin. ", __func__);
    Extension::OnConnect(want);
    sptr<MediaDataShareStubImpl> remoteObject = new (nothrow) MediaDataShareStubImpl(
        static_pointer_cast<MediaDataShareExtAbility>(shared_from_this()),
        nullptr);
    if (remoteObject == nullptr) {
        MEDIA_ERR_LOG("%{public}s No memory allocated for DataShareStubImpl", __func__);
        return nullptr;
    }
    MEDIA_INFO_LOG("%{public}s end.", __func__);
    return remoteObject->AsObject();
}

vector<string> MediaDataShareExtAbility::GetFileTypes(const Uri &uri, const string &mimeTypeFilter)
{
    vector<string> ret;
    return ret;
}

static void FillV10Perms(const MediaType mediaType, const bool containsRead, const bool containsWrite,
    vector<string> &perm)
{
    if (containsRead) {
        if (mediaType == MEDIA_TYPE_IMAGE || mediaType == MEDIA_TYPE_VIDEO ||
            mediaType == Media::MEDIA_TYPE_PHOTO || mediaType == Media::MEDIA_TYPE_ALBUM) {
            perm.push_back(PERM_READ_IMAGEVIDEO);
        } else if (mediaType == MEDIA_TYPE_AUDIO) {
            perm.push_back(PERM_READ_AUDIO);
        } else if (mediaType == MEDIA_TYPE_FILE) {
            perm.push_back(PERM_READ_IMAGEVIDEO);
            perm.push_back(PERM_READ_AUDIO);
            perm.push_back(PERM_READ_DOCUMENT);
        }
    }
    if (containsWrite) {
        if (mediaType == MEDIA_TYPE_IMAGE || mediaType == MEDIA_TYPE_VIDEO ||
            mediaType == Media::MEDIA_TYPE_PHOTO || mediaType == Media::MEDIA_TYPE_ALBUM) {
            perm.push_back(PERM_WRITE_IMAGEVIDEO);
        } else if (mediaType == MEDIA_TYPE_AUDIO) {
            perm.push_back(PERM_WRITE_AUDIO);
        } else if (mediaType == MEDIA_TYPE_FILE) {
            perm.push_back(PERM_WRITE_IMAGEVIDEO);
            perm.push_back(PERM_WRITE_AUDIO);
            perm.push_back(PERM_WRITE_DOCUMENT);
        }
    }
}

static void FillDeprecatedPerms(const bool containsRead, const bool containsWrite, vector<string> &perm)
{
    if (containsRead) {
        perm.push_back(PERMISSION_NAME_READ_MEDIA);
    }
    if (containsWrite) {
        perm.push_back(PERMISSION_NAME_WRITE_MEDIA);
    }
}

static inline bool ContainsFlag(const string &mode, const char flag)
{
    return mode.find(flag) != string::npos;
}

static void CollectPermissionInfo(MediaLibraryCommand &cmd, const string &mode,
    const bool permGranted, PermissionUsedType type)
{
    if ((cmd.GetOprnObject() == OperationObject::FILESYSTEM_PHOTO)) {
        if (mode.find("r") != string::npos) {
            PermissionUtils::CollectPermissionInfo(PERM_READ_IMAGEVIDEO, permGranted, type);
        }
        if (mode.find("w") != string::npos) {
            PermissionUtils::CollectPermissionInfo(PERM_WRITE_IMAGEVIDEO, permGranted, type);
        }
    }
}

static int32_t CheckOpenFilePermission(MediaLibraryCommand &cmd, string &mode)
{
    MEDIA_DEBUG_LOG("uri: %{private}s mode: %{private}s", cmd.GetUri().ToString().c_str(), mode.c_str());
    MediaType mediaType = MediaFileUri::GetMediaTypeFromUri(cmd.GetUri().ToString());
    const bool containsRead = ContainsFlag(mode, 'r');
    const bool containsWrite = ContainsFlag(mode, 'w');

    vector<string> perms;
    FillV10Perms(mediaType, containsRead, containsWrite, perms);
    if ((cmd.GetOprnObject() == OperationObject::FILESYSTEM_PHOTO)) {
        return PermissionUtils::CheckPhotoCallerPermission(perms)? E_SUCCESS : E_PERMISSION_DENIED;
    }
    int32_t err = (mediaType == MEDIA_TYPE_FILE) ?
        (PermissionUtils::CheckHasPermission(perms) ? E_SUCCESS : E_PERMISSION_DENIED) :
        (PermissionUtils::CheckCallerPermission(perms) ? E_SUCCESS : E_PERMISSION_DENIED);
    if (err == E_SUCCESS) {
        return E_SUCCESS;
    }
    // Try to check deprecated permissions
    perms.clear();
    FillDeprecatedPerms(containsRead, containsWrite, perms);
    return PermissionUtils::CheckCallerPermission(perms) ? E_SUCCESS : E_PERMISSION_DENIED;
}

static inline void AddHiddenAlbumPermission(MediaLibraryCommand &cmd, vector<string> &outPerms)
{
    Media::OperationType type = cmd.GetOprnType();
    if (type == Media::OperationType::QUERY_HIDDEN) {
        outPerms.push_back(PERM_MANAGE_PRIVATE_PHOTOS);
    }
}

static int32_t SystemApiCheck(MediaLibraryCommand &cmd)
{
    static const set<OperationObject> SYSTEM_API_OBJECTS = {
        OperationObject::UFM_PHOTO,
        OperationObject::UFM_AUDIO,
        OperationObject::UFM_ALBUM,
        OperationObject::UFM_MAP,
        OperationObject::SMART_ALBUM,

        OperationObject::ALL_DEVICE,
        OperationObject::ACTIVE_DEVICE,
        OperationObject::PAH_FORM_MAP,
    };

    static const set<string> SYSTEM_API_URIS = {
        // Deleting asset permanently from system is only allowed for system apps.
        URI_DELETE_PHOTOS,
        // Deleting asset to trash album directly without a pop-up box is only allowed for system apps.
        UFM_DELETE_PHOTOS,
        PAH_DELETE_PHOTOS,
    };

    OperationObject obj = cmd.GetOprnObject();
    string uri = cmd.GetUriStringWithoutSegment();
    if (SYSTEM_API_OBJECTS.find(obj) != SYSTEM_API_OBJECTS.end() ||
        (SYSTEM_API_URIS.find(uri) != SYSTEM_API_URIS.end())) {
        if (!PermissionUtils::IsSystemApp()) {
            MEDIA_ERR_LOG("Systemapi should only be called by system applications!");
            return E_CHECK_SYSTEMAPP_FAIL;
        }
    }
    return E_SUCCESS;
}

#ifdef MEDIALIBRARY_MEDIATOOL_ENABLE
static int32_t MediaToolNativeSACheck(MediaLibraryCommand &cmd)
{
    static const set<OperationObject> MEDIATOOL_OBJECT = {
        OperationObject::TOOL_PHOTO,
        OperationObject::TOOL_AUDIO
    };
    static const set<Media::OperationType> MEDIATOOL_TYPES = {
        Media::OperationType::DELETE_TOOL
    };

    OperationObject oprnObject = cmd.GetOprnObject();
    Media::OperationType oprnType = cmd.GetOprnType();
    if (MEDIATOOL_OBJECT.find(oprnObject) != MEDIATOOL_OBJECT.end() ||
        MEDIATOOL_TYPES.find(oprnType) != MEDIATOOL_TYPES.end()) {
        if (!PermissionUtils::IsNativeSAApp()) {
            MEDIA_ERR_LOG("Native sa check failed!");
            return E_CHECK_NATIVE_SA_FAIL;
        }
    } else {
        return E_NEED_FURTHER_CHECK;
    }
    return E_SUCCESS;
}
#endif

static inline int32_t HandleMediaVolumePerm()
{
    return PermissionUtils::CheckCallerPermission(PERMISSION_NAME_READ_MEDIA) ? E_SUCCESS : E_PERMISSION_DENIED;
}

static inline int32_t HandleBundlePermCheck()
{
    bool ret = PermissionUtils::CheckCallerPermission(PERMISSION_NAME_WRITE_MEDIA);
    if (ret) {
        return E_SUCCESS;
    }

    return PermissionUtils::CheckHasPermission(WRITE_PERMS_V10) ? E_SUCCESS : E_PERMISSION_DENIED;
}

static int32_t HandleSecurityComponentPermission(MediaLibraryCommand &cmd)
{
    if (cmd.GetUri().ToString().find(OPRN_CREATE_COMPONENT) != string::npos) {
#ifdef MEDIALIBRARY_SECURITY_OPEN
        auto tokenId = PermissionUtils::GetTokenId();
        if (!Security::SecurityComponent::SecCompKit::VerifySavePermission(tokenId)) {
            return E_NEED_FURTHER_CHECK;
        }
        return E_SUCCESS;
#else
        MEDIA_ERR_LOG("Security component is not existed");
        return E_NEED_FURTHER_CHECK;
#endif
    }
    return E_NEED_FURTHER_CHECK;
}

static int32_t UserFileMgrPermissionCheck(MediaLibraryCommand &cmd, const bool isWrite)
{
    static const set<OperationObject> USER_FILE_MGR_OBJECTS = {
        OperationObject::UFM_PHOTO,
        OperationObject::UFM_AUDIO,
        OperationObject::UFM_ALBUM,
        OperationObject::UFM_MAP,
    };

    OperationObject obj = cmd.GetOprnObject();
    if (USER_FILE_MGR_OBJECTS.find(obj) == USER_FILE_MGR_OBJECTS.end()) {
        return E_NEED_FURTHER_CHECK;
    }

    int32_t err = HandleSecurityComponentPermission(cmd);
    if (err == E_SUCCESS || (err != SUCCESS && err != E_NEED_FURTHER_CHECK)) {
        return err;
    }

    vector<string> perms;
    if (obj == OperationObject::UFM_AUDIO) {
        perms.push_back(isWrite ? PERM_WRITE_AUDIO : PERM_READ_AUDIO);
    } else {
        perms.push_back(isWrite ? PERM_WRITE_IMAGEVIDEO : PERM_READ_IMAGEVIDEO);
    }
    AddHiddenAlbumPermission(cmd, perms);
    return PermissionUtils::CheckCallerPermission(perms) ? E_SUCCESS : E_PERMISSION_DENIED;
}

static int32_t PhotoAccessHelperPermCheck(MediaLibraryCommand &cmd, const bool isWrite)
{
    static const set<OperationObject> PHOTO_ACCESS_HELPER_OBJECTS = {
        OperationObject::PAH_PHOTO,
        OperationObject::PAH_ALBUM,
        OperationObject::PAH_MAP,
        OperationObject::PAH_FORM_MAP,
        OperationObject::ANALYSIS_PHOTO_ALBUM,
        OperationObject::ANALYSIS_PHOTO_MAP,
        OperationObject::VISION_OCR,
        OperationObject::VISION_AESTHETICS,
        OperationObject::VISION_LABEL,
        OperationObject::VISION_VIDEO_LABEL,
        OperationObject::VISION_IMAGE_FACE,
        OperationObject::VISION_FACE_TAG,
        OperationObject::VISION_OBJECT,
        OperationObject::VISION_RECOMMENDATION,
        OperationObject::VISION_SEGMENTATION,
        OperationObject::VISION_COMPOSITION,
        OperationObject::VISION_SALIENCY,
        OperationObject::VISION_HEAD,
        OperationObject::VISION_POSE,
        OperationObject::GEO_DICTIONARY,
        OperationObject::GEO_KNOWLEDGE,
        OperationObject::GEO_PHOTO,
        OperationObject::PAH_MULTISTAGES_CAPTURE,
        OperationObject::STORY_ALBUM,
        OperationObject::STORY_COVER,
        OperationObject::STORY_PLAY,
        OperationObject::USER_PHOTOGRAPHY,
    };

    int32_t err = HandleSecurityComponentPermission(cmd);
    if (err == E_SUCCESS || (err != SUCCESS && err != E_NEED_FURTHER_CHECK)) {
        return err;
    }

    OperationObject obj = cmd.GetOprnObject();
    if (PHOTO_ACCESS_HELPER_OBJECTS.find(obj) == PHOTO_ACCESS_HELPER_OBJECTS.end()) {
        return E_NEED_FURTHER_CHECK;
    }
    vector<string> perms;
    AddHiddenAlbumPermission(cmd, perms);
    perms.push_back(isWrite ? PERM_WRITE_IMAGEVIDEO : PERM_READ_IMAGEVIDEO);
    return PermissionUtils::CheckCallerPermission(perms) ? E_SUCCESS : E_PERMISSION_DENIED;
}

static int32_t HandleNoPermCheck(MediaLibraryCommand &cmd)
{
    static const set<string> NO_NEED_PERM_CHECK_URI = {
        URI_CLOSE_FILE,
        MEDIALIBRARY_DIRECTORY_URI,
    };

    static const set<OperationObject> NO_NEED_PERM_CHECK_OBJ = {
        OperationObject::ALL_DEVICE,
        OperationObject::ACTIVE_DEVICE,
    };

    string uri = cmd.GetUri().ToString();
    OperationObject obj = cmd.GetOprnObject();
    if (NO_NEED_PERM_CHECK_URI.find(uri) != NO_NEED_PERM_CHECK_URI.end() ||
        NO_NEED_PERM_CHECK_OBJ.find(obj) != NO_NEED_PERM_CHECK_OBJ.end()) {
        return E_SUCCESS;
    }
    return E_NEED_FURTHER_CHECK;
}

static int32_t HandleSpecialObjectPermission(MediaLibraryCommand &cmd, bool isWrite)
{
    int err = HandleNoPermCheck(cmd);
    if (err == E_SUCCESS || (err != SUCCESS && err != E_NEED_FURTHER_CHECK)) {
        return err;
    }

    OperationObject obj = cmd.GetOprnObject();
    if (obj == OperationObject::MEDIA_VOLUME) {
        return HandleMediaVolumePerm();
    } else if (obj == OperationObject::BUNDLE_PERMISSION) {
        return HandleBundlePermCheck();
    }

    return E_NEED_FURTHER_CHECK;
}

static void UnifyOprnObject(MediaLibraryCommand &cmd)
{
    static const unordered_map<OperationObject, OperationObject> UNIFY_OP_OBJECT_MAP = {
        { OperationObject::UFM_PHOTO, OperationObject::FILESYSTEM_PHOTO },
        { OperationObject::UFM_AUDIO, OperationObject::FILESYSTEM_AUDIO },
        { OperationObject::UFM_ALBUM, OperationObject::PHOTO_ALBUM },
        { OperationObject::UFM_MAP, OperationObject::PHOTO_MAP },
        { OperationObject::PAH_PHOTO, OperationObject::FILESYSTEM_PHOTO },
        { OperationObject::PAH_ALBUM, OperationObject::PHOTO_ALBUM },
        { OperationObject::PAH_MAP, OperationObject::PHOTO_MAP },
#ifdef MEDIALIBRARY_MEDIATOOL_ENABLE
        { OperationObject::TOOL_PHOTO, OperationObject::FILESYSTEM_PHOTO },
        { OperationObject::TOOL_AUDIO, OperationObject::FILESYSTEM_AUDIO },
#endif
    };

    OperationObject obj = cmd.GetOprnObject();
    if (UNIFY_OP_OBJECT_MAP.find(obj) != UNIFY_OP_OBJECT_MAP.end()) {
        cmd.SetOprnObject(UNIFY_OP_OBJECT_MAP.at(obj));
    }
}

static int32_t CheckPermFromUri(MediaLibraryCommand &cmd, bool isWrite)
{
    MEDIA_DEBUG_LOG("uri: %{private}s object: %{public}d, opType: %{public}d isWrite: %{public}d",
        cmd.GetUri().ToString().c_str(), cmd.GetOprnObject(), cmd.GetOprnType(), isWrite);

    int err = SystemApiCheck(cmd);
    if (err != E_SUCCESS) {
        return err;
    }
#ifdef MEDIALIBRARY_MEDIATOOL_ENABLE
    err = MediaToolNativeSACheck(cmd);
    if (err == E_SUCCESS || (err != E_SUCCESS && err != E_NEED_FURTHER_CHECK)) {
        UnifyOprnObject(cmd);
        return err;
    }
#endif
    err = PhotoAccessHelperPermCheck(cmd, isWrite);
    if (err == E_SUCCESS || (err != E_SUCCESS && err != E_NEED_FURTHER_CHECK)) {
        UnifyOprnObject(cmd);
        return err;
    }
    err = UserFileMgrPermissionCheck(cmd, isWrite);
    if (err == E_SUCCESS || (err != E_SUCCESS && err != E_NEED_FURTHER_CHECK)) {
        UnifyOprnObject(cmd);
        return err;
    }
    err = HandleSpecialObjectPermission(cmd, isWrite);
    if (err == E_SUCCESS || (err != E_SUCCESS && err != E_NEED_FURTHER_CHECK)) {
        UnifyOprnObject(cmd);
        return err;
    }

    // Finally, we should check the permission of medialibrary interfaces.
    string perm = isWrite ? PERMISSION_NAME_WRITE_MEDIA : PERMISSION_NAME_READ_MEDIA;
    err = PermissionUtils::CheckCallerPermission(perm) ? E_SUCCESS : E_PERMISSION_DENIED;
    if (err < 0) {
        return err;
    }
    UnifyOprnObject(cmd);
    return E_SUCCESS;
}

static bool IsDeveloperMediaTool(MediaLibraryCommand &cmd)
{
    OperationObject object = cmd.GetOprnObject();
    if (object != OperationObject::TOOL_AUDIO && object != OperationObject::TOOL_PHOTO) {
        return false;
    }
    static const unordered_map<OperationObject, OperationObject> UNIFY_TOOL_OP_OBJECT_MAP = {
        { OperationObject::TOOL_PHOTO, OperationObject::FILESYSTEM_PHOTO },
        { OperationObject::TOOL_AUDIO, OperationObject::FILESYSTEM_AUDIO },
    };
    if (UNIFY_TOOL_OP_OBJECT_MAP.find(object) != UNIFY_TOOL_OP_OBJECT_MAP.end()) {
        cmd.SetOprnObject(UNIFY_TOOL_OP_OBJECT_MAP.at(object));
    }
    if (!PermissionUtils::IsRootShell()) {
        return false;
    }
    if (!OHOS::system::GetBoolParameter("const.security.developermode.state", true)) {
        return false;
    }
    return true;
}

static string GetClientAppId()
{
    string bundleName = MediaLibraryBundleManager::GetInstance()->GetClientBundleName();
    return PermissionUtils::GetAppIdByBundleName(bundleName);
}

static bool CheckIsOwner(const Uri &uri, MediaLibraryCommand &cmd)
{
    auto ret = false;
    if (cmd.GetTableName() == PhotoColumn::PHOTOS_TABLE || cmd.GetTableName() == AudioColumn::AUDIOS_TABLE ||
        cmd.GetTableName() == MEDIALIBRARY_TABLE) {
        if (cmd.GetOprnObject() == OperationObject::TOOL_PHOTO || cmd.GetOprnObject() == OperationObject::TOOL_AUDIO) {
            if (!IsDeveloperMediaTool(cmd)) {
                return false;
            }
        } else {
            std::vector<std::string> columns;
            DatashareBusinessError businessError;
            int errCode = businessError.GetCode();
            string clientAppId = GetClientAppId();
            string fileId = MediaFileUtils::GetIdFromUri(uri.ToString());
            DataSharePredicates predicates;
            predicates.And()->EqualTo("file_id", fileId);
            predicates.And()->EqualTo("owner_appid", clientAppId);
            auto queryResultSet = MediaLibraryDataManager::GetInstance()->Query(cmd, columns, predicates, errCode);
            auto count = 0;
            queryResultSet->GetRowCount(count);
            if (count != 0) {
                ret = true;
                CollectPermissionInfo(cmd, secuityComponentMode, true,
                    PermissionUsedTypeValue::SECURITY_COMPONENT_TYPE);
            }
        }
    }
    return ret;
}

static bool CheckDeveloperOrOwner(MediaLibraryCommand &cmd, DataSharePredicates &appidPredicates)
{
    if (cmd.GetTableName() != PhotoColumn::PHOTOS_TABLE && cmd.GetTableName() != AudioColumn::AUDIOS_TABLE &&
        cmd.GetTableName() != MEDIALIBRARY_TABLE) {
        return false;
    }
    if (cmd.GetOprnObject() == OperationObject::TOOL_AUDIO || cmd.GetOprnObject() == OperationObject::TOOL_PHOTO) {
        if (!IsDeveloperMediaTool(cmd)) {
            return false;
        }
    } else {
        string clientAppId = GetClientAppId();
        appidPredicates.And()->EqualTo("owner_appid", clientAppId);
    }
    return true;
}

static uint32_t GetFlagFromMode(const string &mode)
{
    if (mode.find("w") != string::npos) {
        return AAFwk::Want::FLAG_AUTH_WRITE_URI_PERMISSION;
    }
    return AAFwk::Want::FLAG_AUTH_READ_URI_PERMISSION;
}

int MediaDataShareExtAbility::OpenFile(const Uri &uri, const string &mode)
{
#ifdef MEDIALIBRARY_COMPATIBILITY
    string realUriStr = MediaFileUtils::GetRealUriFromVirtualUri(uri.ToString());
    Uri realUri(realUriStr);
    MediaLibraryCommand command(realUri, Media::OperationType::OPEN);

#else
    MediaLibraryCommand command(uri, Media::OperationType::OPEN);
#endif

    string unifyMode = mode;
    transform(unifyMode.begin(), unifyMode.end(), unifyMode.begin(), ::tolower);

    int err = CheckOpenFilePermission(command, unifyMode);
    if (err == E_PERMISSION_DENIED) {
        err = UriPermissionOperations::CheckUriPermission(command.GetUriStringWithoutSegment(), unifyMode);
        if (err != E_OK) {
            auto& uriPermissionClient = AAFwk::UriPermissionManagerClient::GetInstance();
            if (uriPermissionClient.VerifyUriPermission(Uri(command.GetUriStringWithoutSegment()),
                GetFlagFromMode(unifyMode), IPCSkeleton::GetCallingTokenID())) {
                CollectPermissionInfo(command, unifyMode, true, PermissionUsedTypeValue::PICKER_TYPE);
                err = E_OK;
            }
        }
        if (err != E_OK) {
            CollectPermissionInfo(command, unifyMode, false, PermissionUsedTypeValue::PICKER_TYPE);
            if (!CheckIsOwner(uri, command)) {
                MEDIA_ERR_LOG("Permission Denied! err = %{public}d", err);
                CollectPermissionInfo(command, secuityComponentMode, false,
                    PermissionUsedTypeValue::SECURITY_COMPONENT_TYPE);
                return err;
            }
        }
    } else if (err < 0) {
        return err;
    }
    int32_t object = static_cast<int32_t>(command.GetOprnObject());
    int32_t type = static_cast<int32_t>(command.GetOprnType());
    DfxTimer dfxTimer(type, object, OPEN_FILE_TIME_OUT, true);
    if (command.GetUri().ToString().find(MEDIA_DATA_DB_THUMBNAIL) != string::npos) {
        command.SetOprnObject(OperationObject::THUMBNAIL);
    }
    if (command.GetUri().ToString().find(MEDIA_DATA_DB_THUMB_ASTC) != string::npos) {
        command.SetOprnObject(OperationObject::THUMBNAIL_ASTC);
    }
    if (command.GetUri().ToString().find(PhotoColumn::PHOTO_CACHE_URI_PREFIX) != string::npos) {
        command.SetOprnObject(OperationObject::FILESYSTEM_PHOTO);
    }
    if (command.GetUri().ToString().find(MEDIA_DATA_DB_HIGHLIGHT) != string::npos) {
        command.SetOprnObject(OperationObject::HIGHLIGHT_COVER);
    }
    return MediaLibraryDataManager::GetInstance()->OpenFile(command, unifyMode);
}

int MediaDataShareExtAbility::OpenRawFile(const Uri &uri, const string &mode)
{
    return 0;
}

int MediaDataShareExtAbility::Insert(const Uri &uri, const DataShareValuesBucket &value)
{
    MediaLibraryCommand cmd(uri);
    int32_t err = CheckPermFromUri(cmd, true);
    if (err != E_SUCCESS) {
        if (!IsDeveloperMediaTool(cmd)) {
            return err;
        }
    }
    int32_t object = static_cast<int32_t>(cmd.GetOprnObject());
    int32_t type = static_cast<int32_t>(cmd.GetOprnType());
    DfxTimer dfxTimer(type, object, COMMON_TIME_OUT, true);
    return MediaLibraryDataManager::GetInstance()->Insert(cmd, value);
}

int MediaDataShareExtAbility::InsertExt(const Uri &uri, const DataShareValuesBucket &value, string &result)
{
    MediaLibraryCommand cmd(uri);
    int32_t err = CheckPermFromUri(cmd, true);
    int32_t type = static_cast<int32_t>(cmd.GetOprnType());
    int32_t object = static_cast<int32_t>(cmd.GetOprnObject());
    if (err < 0) {
        if (!IsDeveloperMediaTool(cmd)) {
            MEDIA_INFO_LOG("permission deny: {%{public}d, %{public}d, %{public}d}", type, object, err);
            return err;
        }
    }

    DfxTimer dfxTimer(type, object, COMMON_TIME_OUT, true);
    return MediaLibraryDataManager::GetInstance()->InsertExt(cmd, value, result);
}

int MediaDataShareExtAbility::Update(const Uri &uri, const DataSharePredicates &predicates,
    const DataShareValuesBucket &value)
{
    MediaLibraryCommand cmd(uri);
    int32_t err = CheckPermFromUri(cmd, true);
    int32_t type = static_cast<int32_t>(cmd.GetOprnType());
    int32_t object = static_cast<int32_t>(cmd.GetOprnObject());

    DataSharePredicates appidPredicates = predicates;
    if (err != E_SUCCESS) {
        if (!CheckDeveloperOrOwner(cmd, appidPredicates)) {
            MEDIA_INFO_LOG("permission deny: {%{public}d, %{public}d, %{public}d}", type, object, err);
            return err;
        }
    }

    DfxTimer dfxTimer(type, object, COMMON_TIME_OUT, true);
    auto updateRet = MediaLibraryDataManager::GetInstance()->Update(cmd, value, appidPredicates);
    if (err < 0 && updateRet <= 0) {
        MEDIA_INFO_LOG("permission deny: {%{public}d, %{public}d, %{public}d}", type, object, err);
        return err;
    }
    return updateRet;
}

int MediaDataShareExtAbility::Delete(const Uri &uri, const DataSharePredicates &predicates)
{
    MediaLibraryCommand cmd(uri, Media::OperationType::DELETE);
    int err = CheckPermFromUri(cmd, true);
    int32_t type = static_cast<int32_t>(cmd.GetOprnType());
    int32_t object = static_cast<int32_t>(cmd.GetOprnObject());
    if (err != E_SUCCESS) {
        if (!IsDeveloperMediaTool(cmd)) {
            MEDIA_INFO_LOG("permission deny: {%{public}d, %{public}d, %{public}d}", type, object, err);
            return err;
        }
    }

    DfxTimer dfxTimer(type, object, COMMON_TIME_OUT, true);
    return MediaLibraryDataManager::GetInstance()->Delete(cmd, predicates);
}

shared_ptr<DataShareResultSet> MediaDataShareExtAbility::Query(const Uri &uri,
    const DataSharePredicates &predicates, vector<string> &columns, DatashareBusinessError &businessError)
{
    MediaLibraryCommand cmd(uri);
    int32_t object = static_cast<int32_t>(cmd.GetOprnObject());
    int32_t type = static_cast<int32_t>(cmd.GetOprnType());
    DfxTimer dfxTimer(type, object, COMMON_TIME_OUT, true);
    int32_t err = CheckPermFromUri(cmd, false);
    int errCode = businessError.GetCode();
    DataSharePredicates appidPredicates = predicates;
    if (err != E_SUCCESS) {
        auto& uriPermissionClient = AAFwk::UriPermissionManagerClient::GetInstance();
        if (uriPermissionClient.VerifyUriPermission(uri, AAFwk::Want::FLAG_AUTH_READ_URI_PERMISSION,
            IPCSkeleton::GetCallingTokenID())) {
            MEDIA_DEBUG_LOG("Permission check pass , uri = %{private}s", uri.ToString().c_str());
        } else {
            if (!CheckDeveloperOrOwner(cmd, appidPredicates)) {
                MEDIA_INFO_LOG("permission deny: {%{public}d, %{public}d, %{public}d}", type, object, err);
                businessError.SetCode(err);
                return nullptr;
            }
        }
    }
    auto queryResultSet = MediaLibraryDataManager::GetInstance()->Query(cmd, columns, appidPredicates, errCode);
    businessError.SetCode(to_string(errCode));
    if (queryResultSet == nullptr) {
        MEDIA_ERR_LOG("queryResultSet is nullptr! errCode: %{public}d", errCode);
        businessError.SetCode(errCode);
        return nullptr;
    }
    auto count = 0;
    queryResultSet->GetRowCount(count);
    if (err < 0 && count == 0) {
        businessError.SetCode(err);
        return nullptr;
    }
    shared_ptr<DataShareResultSet> resultSet = make_shared<DataShareResultSet>(queryResultSet);
    return resultSet;
}

string MediaDataShareExtAbility::GetType(const Uri &uri)
{
    MEDIA_INFO_LOG("%{public}s begin.", __func__);
    auto ret = MediaLibraryDataManager::GetInstance()->GetType(uri);
    MEDIA_INFO_LOG("%{public}s end.", __func__);
    return ret;
}

int MediaDataShareExtAbility::BatchInsert(const Uri &uri, const vector<DataShareValuesBucket> &values)
{
    MediaLibraryCommand cmd(uri);
    int32_t err = CheckPermFromUri(cmd, true);
    int32_t type = static_cast<int32_t>(cmd.GetOprnType());
    int32_t object = static_cast<int32_t>(cmd.GetOprnObject());
    if (err != E_SUCCESS) {
        MEDIA_INFO_LOG("permission deny: {%{public}d, %{public}d, %{public}d}", type, object, err);
        return err;
    }
    DfxTimer dfxTimer(type, object, COMMON_TIME_OUT, true);
    return MediaLibraryDataManager::GetInstance()->BatchInsert(cmd, values);
}

bool MediaDataShareExtAbility::RegisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    MEDIA_INFO_LOG("%{public}s begin.", __func__);
    auto obsMgrClient = DataObsMgrClient::GetInstance();
    if (obsMgrClient == nullptr) {
        MEDIA_ERR_LOG("%{public}s obsMgrClient is nullptr", __func__);
        return false;
    }

    ErrCode ret = obsMgrClient->RegisterObserver(uri, dataObserver);
    if (ret != ERR_OK) {
        MEDIA_ERR_LOG("%{public}s obsMgrClient->RegisterObserver error return %{public}d", __func__, ret);
        return false;
    }
    MEDIA_INFO_LOG("%{public}s end.", __func__);
    return true;
}

bool MediaDataShareExtAbility::UnregisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    MEDIA_INFO_LOG("%{public}s begin.", __func__);
    auto obsMgrClient = DataObsMgrClient::GetInstance();
    if (obsMgrClient == nullptr) {
        MEDIA_ERR_LOG("%{public}s obsMgrClient is nullptr", __func__);
        return false;
    }

    ErrCode ret = obsMgrClient->UnregisterObserver(uri, dataObserver);
    if (ret != ERR_OK) {
        MEDIA_ERR_LOG("%{public}s obsMgrClient->UnregisterObserver error return %{public}d", __func__, ret);
        return false;
    }
    MEDIA_INFO_LOG("%{public}s end.", __func__);
    return true;
}

bool MediaDataShareExtAbility::NotifyChange(const Uri &uri)
{
    auto obsMgrClient = DataObsMgrClient::GetInstance();
    if (obsMgrClient == nullptr) {
        MEDIA_ERR_LOG("%{public}s obsMgrClient is nullptr", __func__);
        return false;
    }

    ErrCode ret = obsMgrClient->NotifyChange(uri);
    if (ret != ERR_OK) {
        MEDIA_ERR_LOG("%{public}s obsMgrClient->NotifyChange error return %{public}d", __func__, ret);
        return false;
    }
    return true;
}

Uri MediaDataShareExtAbility::NormalizeUri(const Uri &uri)
{
    MEDIA_INFO_LOG("%{public}s begin.", __func__);
    auto ret = uri;
    MEDIA_INFO_LOG("%{public}s end.", __func__);
    return ret;
}

Uri MediaDataShareExtAbility::DenormalizeUri(const Uri &uri)
{
    MEDIA_INFO_LOG("%{public}s begin.", __func__);
    auto ret = uri;
    MEDIA_INFO_LOG("%{public}s end.", __func__);
    return ret;
}
} // namespace AbilityRuntime
} // namespace OHOS
