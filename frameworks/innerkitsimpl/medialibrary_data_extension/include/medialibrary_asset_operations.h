/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef MEDIALIBRARY_FILE_OPERATIONS
#define MEDIALIBRARY_FILE_OPERATIONS

#include <memory>
#include <string>
#include <vector>
#include <unordered_map>

#include "abs_predicates.h"
#include "abs_shared_result_set.h"
#include "datashare_predicates.h"
#include "datashare_values_bucket.h"
#include "file_asset.h"
#include "imedia_scanner_callback.h"
#include "media_column.h"
#include "medialibrary_async_worker.h"
#include "medialibrary_command.h"
#include "photo_album.h"
#include "picture.h"
#include "value_object.h"
#include "values_bucket.h"
#include "medialibrary_rdb_transaction.h"
#include "asset_accurate_refresh.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
EXPORT const std::unordered_map<std::string, int> FILEASSET_MEMBER_MAP = {
    { MediaColumn::MEDIA_ID, MEMBER_TYPE_INT32 },
    { MediaColumn::MEDIA_FILE_PATH, MEMBER_TYPE_STRING },
    { MediaColumn::MEDIA_SIZE, MEMBER_TYPE_INT64 },
    { MediaColumn::MEDIA_TITLE, MEMBER_TYPE_STRING },
    { MediaColumn::MEDIA_NAME, MEMBER_TYPE_STRING },
    { MediaColumn::MEDIA_TYPE, MEMBER_TYPE_INT32 },
    { MediaColumn::MEDIA_MIME_TYPE, MEMBER_TYPE_STRING },
    { MediaColumn::MEDIA_OWNER_PACKAGE, MEMBER_TYPE_STRING },
    { MediaColumn::MEDIA_OWNER_APPID, MEMBER_TYPE_STRING },
    { MediaColumn::MEDIA_PACKAGE_NAME, MEMBER_TYPE_STRING },
    { MediaColumn::MEDIA_DEVICE_NAME, MEMBER_TYPE_STRING },
    { MediaColumn::MEDIA_DATE_ADDED, MEMBER_TYPE_INT64 },
    { MediaColumn::MEDIA_DATE_MODIFIED, MEMBER_TYPE_INT64 },
    { MediaColumn::MEDIA_DATE_TAKEN, MEMBER_TYPE_INT64 },
    { MediaColumn::MEDIA_DATE_DELETED, MEMBER_TYPE_INT64 },
    { MediaColumn::MEDIA_DURATION, MEMBER_TYPE_INT32 },
    { MediaColumn::MEDIA_TIME_PENDING, MEMBER_TYPE_INT64 },
    { MediaColumn::MEDIA_IS_FAV, MEMBER_TYPE_INT32 },
    { MediaColumn::MEDIA_DATE_TRASHED, MEMBER_TYPE_INT64 },
    { MediaColumn::MEDIA_HIDDEN, MEMBER_TYPE_INT32 },
    { MediaColumn::MEDIA_PARENT_ID, MEMBER_TYPE_INT32 },
    { MediaColumn::MEDIA_RELATIVE_PATH, MEMBER_TYPE_STRING },
    { MediaColumn::MEDIA_VIRTURL_PATH, MEMBER_TYPE_STRING },
    { PhotoColumn::PHOTO_ORIENTATION, MEMBER_TYPE_INT32 },
    { PhotoColumn::PHOTO_LATITUDE, MEMBER_TYPE_DOUBLE },
    { PhotoColumn::PHOTO_LONGITUDE, MEMBER_TYPE_DOUBLE },
    { PhotoColumn::PHOTO_HEIGHT, MEMBER_TYPE_INT32 },
    { PhotoColumn::PHOTO_WIDTH, MEMBER_TYPE_INT32 },
    { PhotoColumn::PHOTO_ALL_EXIF, MEMBER_TYPE_STRING },
    { PhotoColumn::PHOTO_LCD_VISIT_TIME, MEMBER_TYPE_INT64 },
    { PhotoColumn::PHOTO_EDIT_TIME, MEMBER_TYPE_INT64 },
    { PhotoColumn::PHOTO_SUBTYPE, MEMBER_TYPE_INT32 },
    { PhotoColumn::PHOTO_ORIGINAL_SUBTYPE, MEMBER_TYPE_INT32 },
    { PhotoColumn::MOVING_PHOTO_EFFECT_MODE, MEMBER_TYPE_INT32 },
    { PhotoColumn::PHOTO_COVER_POSITION, MEMBER_TYPE_INT64 },
    { PhotoColumn::PHOTO_CE_AVAILABLE, MEMBER_TYPE_INT32 },
    { AudioColumn::AUDIO_ALBUM, MEMBER_TYPE_STRING },
    { AudioColumn::AUDIO_ARTIST, MEMBER_TYPE_STRING },
    { PhotoColumn::PHOTO_OWNER_ALBUM_ID, MEMBER_TYPE_INT32 },
    { PhotoColumn::PHOTO_BURST_KEY, MEMBER_TYPE_STRING },
    { PhotoColumn::PHOTO_BURST_COVER_LEVEL, MEMBER_TYPE_INT32 },
    { PhotoColumn::PHOTO_THUMBNAIL_READY, MEMBER_TYPE_INT64 },
    { PhotoColumn::PHOTO_POSITION, MEMBER_TYPE_INT32 },
    { PhotoColumn::SUPPORTED_WATERMARK_TYPE, MEMBER_TYPE_INT32 },
    { PhotoColumn::PHOTO_SOURCE_PATH, MEMBER_TYPE_STRING },
    { PhotoColumn::PHOTO_DIRTY, MEMBER_TYPE_INT32 },
    { PhotoColumn::PHOTO_CLOUD_ID, MEMBER_TYPE_STRING },
    { PhotoColumn::PHOTO_META_DATE_MODIFIED, MEMBER_TYPE_INT64 },
    { PhotoColumn::PHOTO_SYNC_STATUS, MEMBER_TYPE_INT32 },
    { PhotoColumn::PHOTO_CLOUD_VERSION, MEMBER_TYPE_INT64 },
    { PhotoColumn::CAMERA_SHOT_KEY, MEMBER_TYPE_STRING },
    { PhotoColumn::PHOTO_USER_COMMENT, MEMBER_TYPE_STRING },
    { PhotoColumn::PHOTO_DATE_YEAR, MEMBER_TYPE_STRING },
    { PhotoColumn::PHOTO_DATE_MONTH, MEMBER_TYPE_STRING },
    { PhotoColumn::PHOTO_DATE_DAY, MEMBER_TYPE_STRING },
    { PhotoColumn::PHOTO_SHOOTING_MODE, MEMBER_TYPE_STRING },
    { PhotoColumn::PHOTO_SHOOTING_MODE_TAG, MEMBER_TYPE_STRING },
    { PhotoColumn::PHOTO_LAST_VISIT_TIME, MEMBER_TYPE_INT64 },
    { PhotoColumn::PHOTO_HIDDEN_TIME, MEMBER_TYPE_INT64 },
    { PhotoColumn::PHOTO_THUMB_STATUS, MEMBER_TYPE_INT32 },
    { PhotoColumn::PHOTO_CLEAN_FLAG, MEMBER_TYPE_INT32 },
    { PhotoColumn::PHOTO_ID, MEMBER_TYPE_STRING },
    { PhotoColumn::PHOTO_QUALITY, MEMBER_TYPE_INT32 },
    { PhotoColumn::PHOTO_FIRST_VISIT_TIME, MEMBER_TYPE_INT64 },
    { PhotoColumn::PHOTO_DEFERRED_PROC_TYPE, MEMBER_TYPE_INT32 },
    { PhotoColumn::PHOTO_DYNAMIC_RANGE_TYPE, MEMBER_TYPE_INT32 },
    { PhotoColumn::PHOTO_LCD_SIZE, MEMBER_TYPE_STRING },
    { PhotoColumn::PHOTO_THUMB_SIZE, MEMBER_TYPE_STRING },
    { PhotoColumn::PHOTO_FRONT_CAMERA, MEMBER_TYPE_STRING },
    { PhotoColumn::PHOTO_IS_TEMP, MEMBER_TYPE_INT32 },
    { PhotoColumn::PHOTO_CE_STATUS_CODE, MEMBER_TYPE_INT32 },
    { PhotoColumn::PHOTO_STRONG_ASSOCIATION, MEMBER_TYPE_INT32 },
    { PhotoColumn::PHOTO_ASSOCIATE_FILE_ID, MEMBER_TYPE_INT32 },
    { PhotoColumn::PHOTO_HAS_CLOUD_WATERMARK, MEMBER_TYPE_INT32 },
    { PhotoColumn::PHOTO_DETAIL_TIME, MEMBER_TYPE_STRING },
    { PhotoColumn::PHOTO_ORIGINAL_ASSET_CLOUD_ID, MEMBER_TYPE_STRING },
    { PhotoColumn::PHOTO_METADATA_FLAGS, MEMBER_TYPE_INT32 },
    { PhotoColumn::PHOTO_IS_AUTO, MEMBER_TYPE_INT32 },
    { PhotoColumn::PHOTO_MEDIA_SUFFIX, MEMBER_TYPE_STRING },
    { PhotoColumn::STAGE_VIDEO_TASK_STATUS, MEMBER_TYPE_INT32 },
};

typedef struct {
    int64_t sizeMp4;
    int64_t sizeExtra;
    int64_t size;
    int64_t dateModified;
    int64_t editTime;
    int32_t subType;
    int32_t effectMode;
    int32_t originalSubType;
    std::string videoPath;
    std::string extraPath;
    std::string editDataPath;
    std::string editDataCameraPath;
    std::string editDataSourcePath;
    std::string path;
    std::string cloudId;
    std::string displayName;
    std::string photoImagePath;
    std::string photoVideoPath;
    std::string cachePath;
} ExternalInfo;

class MediaLibraryAssetOperations {
public:
    static int32_t HandleInsertOperation(MediaLibraryCommand &cmd);
    static int32_t HandleInsertOperationExt(MediaLibraryCommand& cmd);
    static int32_t DeleteOperation(MediaLibraryCommand &cmd);
    static std::shared_ptr<NativeRdb::ResultSet> QueryOperation(MediaLibraryCommand &cmd,
        const std::vector<std::string> &columns);
    EXPORT static int32_t UpdateOperation(MediaLibraryCommand &cmd);
    static int32_t OpenOperation(MediaLibraryCommand &cmd, const std::string &mode);
    static int32_t DeleteToolOperation(MediaLibraryCommand &cmd);

    EXPORT static int32_t CreateAssetBucket(int32_t fileId, int32_t &bucketNum);
    EXPORT static int32_t CreateAssetUniqueId(int32_t type,
        std::shared_ptr<TransactionOperations> trans = nullptr);
    EXPORT static int32_t CreateAssetUniqueIds(int32_t type, int32_t num, int32_t &startUniqueNumber);
    EXPORT static int32_t CreateAssetPathById(int32_t fileId, int32_t mediaType, const std::string &extension,
        std::string &filePath);
    EXPORT static int32_t DeleteFromDisk(NativeRdb::AbsRdbPredicates &predicates, const bool isAging,
        const bool compatible = false);
    EXPORT static int32_t DeletePermanently(NativeRdb::AbsRdbPredicates &predicates, const bool isAging,
        std::shared_ptr<AccurateRefresh::AssetAccurateRefresh> assetRefresh = nullptr);
    EXPORT static int32_t DeleteNormalPhotoPermanently(std::shared_ptr<FileAsset> &fileAsset,
        std::shared_ptr<AccurateRefresh::AssetAccurateRefresh> assetRefresh = nullptr);
    EXPORT static std::string GetEditDataSourcePath(const std::string &path);
    EXPORT static int32_t GetAlbumIdByPredicates(const std::string &whereClause,
        const std::vector<std::string> &whereArgs);
    EXPORT static int32_t CheckExist(const std::string &path);
    EXPORT static int32_t QueryTotalPhoto(std::vector<std::shared_ptr<FileAsset>> &fileAssetVector, int32_t batchSize);
    EXPORT static int32_t QueryTotalAlbum(std::vector<std::shared_ptr<PhotoAlbum>> &PhotoAlbumVector);
    EXPORT static std::shared_ptr<FileAsset> QuerySinglePhoto(int32_t rowId);
    EXPORT static std::vector<std::string> QueryPhotosTableColumnInfo();
    EXPORT static const std::vector<std::string> &GetPhotosTableColumnInfo();
    EXPORT static bool GetInt32FromValuesBucket(const NativeRdb::ValuesBucket &values, const std::string &column,
        int32_t &value);
    EXPORT static bool GetStringFromValuesBucket(const NativeRdb::ValuesBucket &values, const std::string &column,
        std::string &value);
    EXPORT static std::string GetEditDataDirPath(const std::string &path);
    static std::shared_ptr<FileAsset> GetAssetFromResultSet(const std::shared_ptr<NativeRdb::ResultSet> &resultSet,
        const std::vector<std::string> &columns);

protected:
    static std::shared_ptr<FileAsset> GetFileAssetFromDb(const std::string &column, const std::string &value,
        OperationObject oprnObject, const std::vector<std::string> &columns = {}, const std::string &networkId = "");
    static std::shared_ptr<FileAsset> GetFileAssetFromDb(NativeRdb::AbsPredicates &predicates,
        OperationObject oprnObject, const std::vector<std::string> &columns = {}, const std::string &networkId = "");
    EXPORT static int32_t GetFileAssetVectorFromDb(NativeRdb::AbsPredicates &predicates, OperationObject oprnObject,
        std::vector<std::shared_ptr<FileAsset>> &fileAssetVector, const std::vector<std::string> &columns = {},
        const std::string &networkId = "");
    EXPORT static std::shared_ptr<FileAsset> GetFileAssetByUri(const std::string &fileUri, bool isPhoto,
        const std::vector<std::string> &columns, const std::string &pendingStatus = "");

    static int32_t CreateOperation(MediaLibraryCommand &cmd);
    static int32_t CloseOperation(MediaLibraryCommand &cmd);
    static int32_t InsertAssetInDb(std::shared_ptr<TransactionOperations> trans,
        MediaLibraryCommand &cmd, const FileAsset &fileAsset);
    static int32_t CheckWithType(bool isContains, const std::string &displayName,
         const std::string &extention, int32_t mediaType);
    static int32_t CheckDisplayNameWithType(const std::string &displayName, int32_t mediaType);
    static int32_t CheckExtWithType(const std::string &extention, int32_t mediaType);
    static int32_t CheckRelativePathWithType(const std::string &relativePath, int32_t mediaType);
    static void GetAssetRootDir(int32_t mediaType, std::string &rootDirPath);
    EXPORT static int32_t SetAssetPathInCreate(FileAsset &fileAsset,
        std::shared_ptr<TransactionOperations> trans = nullptr);
    EXPORT static int32_t SetAssetPath(FileAsset &fileAsset, const std::string &extention,
        std::shared_ptr<TransactionOperations> trans = nullptr);
    EXPORT static int32_t DeleteAssetInDb(MediaLibraryCommand &cmd,
        std::shared_ptr<AccurateRefresh::AssetAccurateRefresh> assetRefresh = nullptr);

    EXPORT static int32_t UpdateFileName(MediaLibraryCommand &cmd, const std::shared_ptr<FileAsset> &fileAsset,
        bool &isNameChanged);
    EXPORT static int32_t SetUserComment(MediaLibraryCommand &cmd, const std::shared_ptr<FileAsset> &fileAsset);
    EXPORT static int32_t UpdateRelativePath(MediaLibraryCommand &cmd, const std::shared_ptr<FileAsset> &fileAsset,
        bool &isNameChanged);
    static void UpdateVirtualPath(MediaLibraryCommand &cmd, const std::shared_ptr<FileAsset> &fileAsset);
    static int32_t UpdateFileInDb(MediaLibraryCommand &cmd);
    EXPORT static int32_t OpenAsset(const std::shared_ptr<FileAsset> &fileAsset, const std::string &mode,
        MediaLibraryApi api, bool isMovingPhotoVideo = false, int32_t type = -1);
    static int32_t OpenHighlightCover(MediaLibraryCommand &cmd, const std::string &mode);
    static int32_t OpenHighlightVideo(MediaLibraryCommand &cmd, const std::string &mode);
    EXPORT static int32_t CloseAsset(const std::shared_ptr<FileAsset> &fileAsset, bool isCreateThumbSync = false);
    static void InvalidateThumbnail(const std::string &fileId, int32_t mediaType);
    static int32_t SendTrashNotify(MediaLibraryCommand &cmd, int32_t rowId, const std::string &extraUri = "",
        std::shared_ptr<AccurateRefresh::AssetAccurateRefresh> assetRefresh = nullptr);
    static void SendFavoriteNotify(MediaLibraryCommand &cmd, std::shared_ptr<FileAsset> &fileAsset,
        const std::string &extraUri = "",
        std::shared_ptr<AccurateRefresh::AssetAccurateRefresh> assetRefresh = nullptr);
    static void UpdateOwnerAlbumIdOnMove(MediaLibraryCommand &cmd, int32_t &targetAlbumId, int32_t &oriAlbumId);
    static int32_t SendModifyUserCommentNotify(MediaLibraryCommand &cmd, int32_t rowId,
        const std::string &extraUri = "");
    static int32_t SetPendingStatus(MediaLibraryCommand &cmd);
    EXPORT static int32_t GrantUriPermission(const std::string &uri, const std::string &bundleName,
        const std::string &path, bool isMovingPhoto = false);

    EXPORT static std::string CreateExtUriForV10Asset(FileAsset &fileAsset);
    EXPORT static int32_t OpenFileWithPrivacy(const std::string &filePath, const std::string &mode,
        const std::string &fileId, int32_t type = -1);
    static void ScanFile(const std::string &path, bool isCreateThumbSync, bool isInvalidateThumb,
        bool isForceScan = false, int32_t fileId = 0, std::shared_ptr<Media::Picture> resultPicture = nullptr);
    static void ScanFileWithoutAlbumUpdate(const std::string &path, bool isCreateThumbSync, bool isInvalidateThumb,
        bool isForceScan = false, int32_t fileId = 0, std::shared_ptr<Media::Picture> resultPicture = nullptr);

    EXPORT static std::string GetEditDataPath(const std::string &path);
    EXPORT static std::string GetEditDataCameraPath(const std::string &path);
    static std::string GetAssetCacheDir();

private:
    static int32_t CreateAssetRealName(int32_t fileId, int32_t mediaType, const std::string &extension,
        std::string &name);
    static int32_t SetPendingTrue(const std::shared_ptr<FileAsset> &fileAsset);
    static int32_t SetPendingFalse(const std::shared_ptr<FileAsset> &fileAsset);
    static void IsCoverContentChange(string &fileId);

    static constexpr int ASSET_MAX_COMPLEMENT_ID = 999;

    class ScanAssetCallback : public IMediaScannerCallback {
    public:
        ScanAssetCallback() = default;
        ~ScanAssetCallback() = default;
        int32_t OnScanFinished(const int32_t status, const std::string &uri, const std::string &path) override;
        void SetSync(bool isSync)
        {
            isCreateThumbSync = isSync;
        }
        void SetIsInvalidateThumb(bool isInvalidate)
        {
            isInvalidateThumb = isInvalidate;
        }
        void SetOriginalPhotoPicture(std::shared_ptr<Media::Picture> resultPicture)
        {
            originalPhotoPicture = resultPicture;
        }
    private:
        bool isCreateThumbSync = false;
        bool isInvalidateThumb = true;
        std::shared_ptr<Media::Picture> originalPhotoPicture = nullptr;
    };
};

class DeleteFilesTask : public AsyncTaskData {
public:
    DeleteFilesTask(const std::vector<std::string> &ids, const std::vector<std::string> &paths,
        const std::vector<std::string> &notifyUris, const std::vector<std::string> &dateTakens,
        const std::vector<int32_t> &subTypes, const std::string &table, int32_t deleteRows,
        std::string bundleName, bool containsHidden)
        : ids_(ids), paths_(paths), notifyUris_(notifyUris), dateTakens_(dateTakens), subTypes_(subTypes),
        table_(table), deleteRows_(deleteRows), bundleName_(bundleName), containsHidden_(containsHidden) {}
    virtual ~DeleteFilesTask() override = default;
    void SetOtherInfos(const std::map<std::string, std::string> &displayNames,
        const std::map<std::string, std::string> &albumNames, const std::map<std::string, std::string> &ownerAlbumIds)
    {
        displayNames_ = displayNames;
        albumNames_ = albumNames;
        ownerAlbumIds_ = ownerAlbumIds;
    }
    void SetAssetAccurateRefresh(std::shared_ptr<AccurateRefresh::AssetAccurateRefresh> refresh)
    {
        refresh_ = refresh;
    }
    std::vector<std::string> ids_;
    std::vector<std::string> paths_;
    std::vector<std::string> notifyUris_;
    std::vector<std::string> dateTakens_;
    std::vector<int32_t> subTypes_;
    std::vector<int32_t> isTemps_;
    std::string table_;
    int32_t deleteRows_;
    std::string bundleName_;
    std::map<std::string, std::string> displayNames_;
    std::map<std::string, std::string> albumNames_;
    std::map<std::string, std::string> ownerAlbumIds_;
    bool containsHidden_ = false;
    std::shared_ptr<AccurateRefresh::AssetAccurateRefresh> refresh_ = nullptr;
};

class DeleteNotifyAsyncTaskData : public AsyncTaskData {
public:
    DeleteNotifyAsyncTaskData() = default;
    virtual ~DeleteNotifyAsyncTaskData() override = default;
    int32_t updateRows = 0;
    std::vector<std::string> notifyUris;
    std::string notifyUri;
    int64_t trashDate = 0;
    std::shared_ptr<AccurateRefresh::AssetAccurateRefresh> refresh_ = nullptr;
};

using VerifyFunction = bool (*) (NativeRdb::ValueObject&, MediaLibraryCommand&);
class AssetInputParamVerification {
public:
    static bool CheckParamForUpdate(MediaLibraryCommand &cmd);

private:
    static bool Forbidden(NativeRdb::ValueObject &value, MediaLibraryCommand &cmd);
    static bool IsInt32(NativeRdb::ValueObject &value, MediaLibraryCommand &cmd);
    static bool IsInt64(NativeRdb::ValueObject &value, MediaLibraryCommand &cmd);
    static bool IsBool(NativeRdb::ValueObject &value, MediaLibraryCommand &cmd);
    static bool IsString(NativeRdb::ValueObject &value, MediaLibraryCommand &cmd);
    static bool IsDouble(NativeRdb::ValueObject &value, MediaLibraryCommand &cmd);
    static bool IsBelowApi9(NativeRdb::ValueObject &value, MediaLibraryCommand &cmd);
    static bool IsStringNotNull(NativeRdb::ValueObject &value, MediaLibraryCommand &cmd);
    static bool IsUniqueValue(NativeRdb::ValueObject &value, MediaLibraryCommand &cmd);

    static const std::unordered_map<std::string, std::vector<VerifyFunction>> UPDATE_VERIFY_PARAM_MAP;
};
} // namespace Media
} // namespace OHOS

#endif // MEDIALIBRARY_FILE_OPERATIONS