/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_ANI_SRC_INCLUDE_PHOTO_ACCESS_HELPER_ANI_H
#define FRAMEWORKS_ANI_SRC_INCLUDE_PHOTO_ACCESS_HELPER_ANI_H

#include <ani.h>
#include "ani_error.h"
#include "fetch_result_ani.h"
#include "photo_album_ani.h"
#include "medialibrary_ani_utils.h"
#include "smart_album_asset.h"

namespace OHOS {
namespace Media {

class ChangeListenerAni {
public:
    explicit ChangeListenerAni(ani_env *env) : env_(env) {}

private:
    [[maybe_unused]] ani_env *env_ = nullptr;
};

class ThumbnailBatchGenerateObserver : public DataShare::DataShareObserver {
    public:
        ThumbnailBatchGenerateObserver() = default;
        ~ThumbnailBatchGenerateObserver() = default;

        void OnChange(const ChangeInfo &changeInfo) override;
};

using ThreadFunciton = std::function<void(ani_env*, ani_object, void*, void*)>;
class ThumbnailGenerateHandler {
public:
    ThumbnailGenerateHandler(ani_object ref, ThreadFunciton func) : callbackRef_(ref), threadSafeFunc_(func) {}
    ~ThumbnailGenerateHandler() = default;

    ani_object callbackRef_;
    ThreadFunciton threadSafeFunc_;
};

class MediaLibraryAni {
public:
    static ani_status PhotoAccessHelperInit(ani_env *env);
    static ani_object Constructor([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_class clazz,
        [[maybe_unused]] ani_object context);
    static MediaLibraryAni* Unwrap(ani_env *env, ani_object object);

    static ani_object GetPhotoAlbums(ani_env *env, ani_object object, ani_enum_item albumTypeItem,
        ani_enum_item albumSubtypeItem, ani_object fetchOptions);
    static ani_status Release(ani_env *env, ani_object object);
    static ani_status ApplyChanges(ani_env *env, ani_object object);
    static ani_object createAsset1([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object obj,
        [[maybe_unused]] ani_string stringObj);
    static ani_object GetAssetsSync([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object,
        ani_object options);
    static ani_object GetAssetsInner([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object,
        ani_object options);
    static std::mutex sUserFileClientMutex_;
    static void PhotoAccessStopCreateThumbnailTask([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object,
        ani_int taskId);
    static ani_int PhotoAccessStartCreateThumbnailTask([[maybe_unused]] ani_env *env,
        [[maybe_unused]] ani_object object, ani_object predicate);
    static void OnThumbnailGenerated(ani_env *env, ani_object callback, void *context, void *data);

private:
    ani_env *env_;
};

struct PickerCallBack {
    bool ready = false;
    bool isOrigin;
    int32_t resultCode;
    vector<string> uris;
};

constexpr int32_t DEFAULT_PRIVATEALBUMTYPE = 3;

struct MediaLibraryAsyncContext : public AniError {
    bool status;
    bool isDelete;
    bool isCreateByComponent;
    bool isCreateByAgent;
    AniAssetType assetType;
    AlbumType albumType;
    MediaLibraryAni *objectInfo;
    std::string selection;
    std::vector<std::string> selectionArgs;
    std::string order;
    std::string uri;
    std::vector<std::string> uriArray;
    std::string networkId;
    std::string extendArgs;
    std::string analysisProgress;
    int32_t analysisType = AnalysisType::ANALYSIS_INVALID;
    std::unique_ptr<FetchResult<FileAsset>> fetchFileResult;
    std::unique_ptr<FetchResult<AlbumAsset>> fetchAlbumResult;
    std::unique_ptr<FetchResult<PhotoAlbum>> fetchPhotoAlbumResult;
    std::unique_ptr<FetchResult<SmartAlbumAsset>> fetchSmartAlbumResult;
    std::unique_ptr<FileAsset> fileAsset;
    std::unique_ptr<PhotoAlbum> photoAlbumData;
    std::unique_ptr<SmartAlbumAsset> smartAlbumData;
    OHOS::DataShare::DataShareValuesBucket valuesBucket;
    std::vector<OHOS::DataShare::DataShareValuesBucket> valuesBucketArray;
    unsigned int dirType = 0;
    int32_t privateAlbumType = DEFAULT_PRIVATEALBUMTYPE;
    int32_t retVal;
    std::string directoryRelativePath;
    std::vector<std::unique_ptr<AlbumAsset>> albumNativeArray;
    std::vector<std::unique_ptr<SmartAlbumAsset>> smartAlbumNativeArray;
    std::vector<std::unique_ptr<SmartAlbumAsset>> privateSmartAlbumNativeArray;
    std::string storeMediaSrc;
    int32_t imagePreviewIndex;
    int32_t parentSmartAlbumId = 0;
    int32_t smartAlbumId = -1;
    int32_t isLocationAlbum = 0;
    int32_t isHighlightAlbum = 0;
    ResultNapiType resultNapiType;
    std::string tableName;
    std::vector<uint32_t> mediaTypes;
    std::vector<string> mediaTypeNames;
    int32_t photoType;
    OHOS::DataShare::DataSharePredicates predicates;
    std::vector<std::string> fetchColumn;
    std::vector<std::string> uris;
    bool isForce = false;
    bool hiddenOnly = false;
    bool isAnalysisAlbum = false;
    int32_t hiddenAlbumFetchMode = -1;
    std::string formId;
    std::string indexProgress;
    std::shared_ptr<PickerCallBack> pickerCallBack;
    std::vector<std::string> analysisDatas;
    ani_object callback;
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_ANI_SRC_INCLUDE_PHOTO_ACCESS_HELPER_ANI_H
