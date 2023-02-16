/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_MEDIA_LIBRARY_NAPI_H_
#define INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_MEDIA_LIBRARY_NAPI_H_

#include <mutex>

#include "abs_shared_result_set.h"
#include "album_napi.h"
#include "data_ability_helper.h"
#include "data_ability_observer_stub.h"
#include "data_ability_predicates.h"
#include "fetch_file_result_napi.h"
#include "file_asset_napi.h"
#include "napi_base_context.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_error.h"
#include "smart_album_asset.h"
#include "values_bucket.h"
#include "napi_remote_object.h"
#include "datashare_helper.h"
#include "datashare_predicates.h"

namespace OHOS {
namespace Media {
static const std::string MEDIA_LIB_NAPI_CLASS_NAME = "MediaLibrary";
static const std::string USERFILE_MGR_NAPI_CLASS_NAME = "UserFileManager";

enum ListenerType {
    INVALID_LISTENER = -1,

    AUDIO_LISTENER,
    VIDEO_LISTENER,
    IMAGE_LISTENER,
    FILE_LISTENER,
    SMARTALBUM_LISTENER,
    DEVICE_LISTENER,
    REMOTEFILE_LISTENER,
    ALBUM_LISTENER    
};

struct MediaChangeListener {
    MediaType mediaType;
};

class ChangeListenerNapi {
public:
    class UvChangeMsg {
    public:
        UvChangeMsg(napi_env env, napi_ref ref) : env_(env), ref_(ref) {}
        ~UvChangeMsg() {}
        napi_env env_;
        napi_ref ref_;
    };

    explicit ChangeListenerNapi(napi_env env) : env_(env) {}

    ChangeListenerNapi(const ChangeListenerNapi &listener)
    {
        this->env_ = listener.env_;
        this->cbOnRef_ = listener.cbOnRef_;
        this->cbOffRef_ = listener.cbOffRef_;
    }

    ChangeListenerNapi& operator=(const ChangeListenerNapi &listener)
    {
        this->env_ = listener.env_;
        this->cbOnRef_ = listener.cbOnRef_;
        this->cbOffRef_ = listener.cbOffRef_;
        return *this;
    }

    ~ChangeListenerNapi() = default;

    void OnChange(const MediaChangeListener &listener, const napi_ref cbRef);

    napi_ref cbOnRef_ = nullptr;
    napi_ref cbOffRef_ = nullptr;
    sptr<AAFwk::IDataAbilityObserver> audioDataObserver_ = nullptr;
    sptr<AAFwk::IDataAbilityObserver> videoDataObserver_ = nullptr;
    sptr<AAFwk::IDataAbilityObserver> imageDataObserver_ = nullptr;
    sptr<AAFwk::IDataAbilityObserver> fileDataObserver_ = nullptr;
    sptr<AAFwk::IDataAbilityObserver> smartAlbumDataObserver_ = nullptr;
    sptr<AAFwk::IDataAbilityObserver> deviceDataObserver_ = nullptr;
    sptr<AAFwk::IDataAbilityObserver> remoteFileDataObserver_ = nullptr;
    sptr<AAFwk::IDataAbilityObserver> albumDataObserver_ = nullptr;

private:
    napi_env env_ = nullptr;
};

class MediaObserver : public AAFwk::DataAbilityObserverStub {
public:
    MediaObserver(const ChangeListenerNapi &listObj, MediaType mediaType) : listObj_(listObj)
    {
        mediaType_ = mediaType;
    }

    ~MediaObserver() = default;

    void OnChange() override
    {
        MediaChangeListener listener;
        listener.mediaType = mediaType_;
        listObj_.OnChange(listener, listObj_.cbOnRef_);
    }

    ChangeListenerNapi listObj_;
    MediaType mediaType_;
};

class MediaLibraryNapi {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value UserFileMgrInit(napi_env env, napi_value exports);

    MediaLibraryNapi();
    ~MediaLibraryNapi();

    ResultNapiType resultNapiType_;

private:
    static void MediaLibraryNapiDestructor(napi_env env, void *nativeObject, void *finalize_hint);
    static napi_value MediaLibraryNapiConstructor(napi_env env, napi_callback_info info);

    static napi_value GetMediaLibraryNewInstance(napi_env env, napi_callback_info info);

    static napi_value JSGetPublicDirectory(napi_env env, napi_callback_info info);
    static napi_value JSGetFileAssets(napi_env env, napi_callback_info info);
    static napi_value JSGetAlbums(napi_env env, napi_callback_info info);

    static napi_value JSCreateAsset(napi_env env, napi_callback_info info);
    static napi_value JSDeleteAsset(napi_env env, napi_callback_info info);

    static napi_value JSOnCallback(napi_env env, napi_callback_info info);
    static napi_value JSOffCallback(napi_env env, napi_callback_info info);

    static napi_value JSRelease(napi_env env, napi_callback_info info);

    static napi_value JSGetActivePeers(napi_env env, napi_callback_info info);
    static napi_value JSGetAllPeers(napi_env env, napi_callback_info info);
    static napi_value CreateMediaTypeEnum(napi_env env);
    static napi_value CreateFileKeyEnum(napi_env env);
    static napi_value CreateDirectoryTypeEnum(napi_env env);
    static napi_value CreateVirtualAlbumTypeEnum(napi_env env);
    static napi_value CreatePrivateAlbumTypeEnum(napi_env env);

    static napi_value CreateMediaTypeUserFileEnum(napi_env env);

    static napi_value JSGetSmartAlbums(napi_env env, napi_callback_info info);
    static napi_value JSGetPrivateAlbum(napi_env env, napi_callback_info info);
    static napi_value JSCreateSmartAlbum(napi_env env, napi_callback_info info);
    static napi_value JSDeleteSmartAlbum(napi_env env, napi_callback_info info);

    static napi_value JSStoreMediaAsset(napi_env env, napi_callback_info info);
    static napi_value JSStartImagePreview(napi_env env, napi_callback_info info);
    static napi_value JSGetMediaRemoteStub(napi_env env, napi_callback_info info);

    static napi_value GetUserFileMgr(napi_env env, napi_callback_info info);
    static napi_value UserFileMgrCreateAsset(napi_env env, napi_callback_info info);
    static napi_value UserFileMgrTrashAsset(napi_env env, napi_callback_info info);
    static napi_value UserFileMgrGetAlbums(napi_env env, napi_callback_info info);
    static napi_value UserFileMgrGetPhotoAssets(napi_env env, napi_callback_info info);
    static napi_value UserFileMgrGetAudioAssets(napi_env env, napi_callback_info info);
    static napi_value UserFileMgrGetPrivateAlbum(napi_env env, napi_callback_info info);
    static napi_value UserFileMgrCreateFileKeyEnum(napi_env env);
    static napi_value CreateAudioKeyEnum(napi_env env);
    static napi_value CreateImageVideoKeyEnum(napi_env env);
    static napi_value CreateAlbumKeyEnum(napi_env env);

    int32_t GetListenerType(const std::string &str) const;
    void RegisterChange(napi_env env, const std::string &type, ChangeListenerNapi &listObj);
    void UnregisterChange(napi_env env, const std::string &type, ChangeListenerNapi &listObj);

    napi_env env_;

    static thread_local napi_ref sConstructor_;
    static thread_local napi_ref userFileMgrConstructor_;
    static thread_local napi_ref sMediaTypeEnumRef_;
    static thread_local napi_ref sDirectoryEnumRef_;
    static thread_local napi_ref sVirtualAlbumTypeEnumRef_;
    static thread_local napi_ref sFileKeyEnumRef_;
    static thread_local napi_ref sPrivateAlbumEnumRef_;

    static thread_local napi_ref sUserFileMgrFileKeyEnumRef_;
    static thread_local napi_ref sAudioKeyEnumRef_;
    static thread_local napi_ref sImageVideoKeyEnumRef_;
    static thread_local napi_ref sAlbumKeyEnumRef_;

    static std::mutex sUserFileClientMutex_;
};

const int32_t DEFAULT_PRIVATEALBUMTYPE = 3;
struct MediaLibraryAsyncContext : public NapiError {
    napi_async_work work;
    napi_deferred deferred;
    napi_ref callbackRef;
    bool status;
    bool isDelete;
    NapiAssetType assetType;
    AlbumType albumType;
    MediaLibraryNapi *objectInfo;
    std::string selection;
    std::vector<std::string> selectionArgs;
    std::string order;
    std::string uri;
    std::string networkId;
    std::string extendArgs;
    std::unique_ptr<FetchResult<FileAsset>> fetchFileResult;
    std::unique_ptr<FetchResult<AlbumAsset>> fetchAlbumResult;
    std::unique_ptr<FetchResult<SmartAlbumAsset>> fetchSmartAlbumResult;
    std::unique_ptr<FileAsset> fileAsset;
    std::unique_ptr<SmartAlbumAsset> smartAlbumData;
    OHOS::DataShare::DataShareValuesBucket valuesBucket;
    unsigned int dirType = 0;
    int32_t privateAlbumType = DEFAULT_PRIVATEALBUMTYPE;
    int32_t retVal;
    std::string directoryRelativePath;
    std::vector<std::unique_ptr<AlbumAsset>> albumNativeArray;
    std::vector<std::unique_ptr<SmartAlbumAsset>> smartAlbumNativeArray;
    std::vector<std::unique_ptr<SmartAlbumAsset>> privateSmartAlbumNativeArray;
    Ability *ability_;
    std::string storeMediaSrc;
    int32_t imagePreviewIndex;

    size_t argc;
    napi_value argv[NAPI_ARGC_MAX];
    ResultNapiType resultNapiType;
    std::string typeMask;
    std::vector<uint32_t> mediaTypes;
    OHOS::DataShare::DataSharePredicates predicates;
    std::vector<std::string> fetchColumn;
};
} // namespace Media
} // namespace OHOS

#endif  // INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_MEDIA_LIBRARY_NAPI_H_
