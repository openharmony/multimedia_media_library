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

#ifndef OHOS_MEDIA_CLONE_RESTORE_H
#define OHOS_MEDIA_CLONE_RESTORE_H

#include <optional>
#include <type_traits>
#include <set>
#include <sstream>
#include <algorithm>
#include <iterator>
#include <vector>

#include "base_restore.h"
#include "backup_const.h"
#include "clone_restore_cv_analysis.h"
#include "clone_restore_highlight.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_errno.h"
#include "medialibrary_kvstore_manager.h"
#include "backup_database_utils.h"
#include "photo_album_clone.h"
#include "photos_clone.h"
#include "clone_restore_geo.h"

namespace OHOS {
namespace Media {
class CloneRestore : public BaseRestore {
public:
    CloneRestore();
    virtual ~CloneRestore() = default;
    // upgradePath is useless now
    void StartRestore(const std::string &backupRestorePath, const std::string &upgradePath) override;
    int32_t Init(const std::string &backupRestoreDir, const std::string &upgradeFilePath, bool isUpgrade) override;
    NativeRdb::ValuesBucket GetInsertValue(const FileInfo &fileInfo, const std::string &newPath,
        int32_t sourceType) override;
    std::string GetBackupInfo() override;
    void StartBackup() override;
    using CoverUriInfo = std::pair<std::string, std::pair<std::string, int32_t>>;

private:
    void RestorePhoto(void) override;
    void HandleRestData(void) override;
    std::vector<FileInfo> QueryFileInfos(int32_t offset, int32_t isRelatedToPhotoMap = 0);
    bool ParseResultSet(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, FileInfo &info,
        std::string dbName = "") override;
    bool ParseResultSetForAudio(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, FileInfo &info) override;
    void AnalyzeSource() override;
    void RestoreAlbum(void);
    void RestoreAudio(void) override;
    int InsertPhoto(std::vector<FileInfo> &fileInfos);
    std::vector<NativeRdb::ValuesBucket> GetInsertValues(int32_t sceneCode, std::vector<FileInfo> &fileInfos,
        int32_t sourceType);
    std::vector<NativeRdb::ValuesBucket> GetInsertValues(std::vector<AnalysisAlbumTbl> &analysisAlbumTbl);
    int32_t MoveAsset(FileInfo &fileInfo);
    bool IsFilePathExist(const std::string &filePath) const;
    int32_t QueryTotalNumber(const std::string &tableName);
    std::vector<AlbumInfo> QueryAlbumInfos(const std::string &tableName, int32_t offset);
    bool ParseAlbumResultSet(const std::string &tableName, const std::shared_ptr<NativeRdb::ResultSet> &resultSet,
        AlbumInfo &albumInfo);
    bool PrepareCommonColumnInfoMap(const std::string &tableName,
        const std::unordered_map<std::string, std::string> &srcColumnInfoMap,
        const std::unordered_map<std::string, std::string> &dstColumnInfoMap);
    bool HasSameColumn(const std::unordered_map<std::string, std::string> &columnInfoMap, const std::string &columnName,
        const std::string &columnType);
    void GetValFromResultSet(const std::shared_ptr<NativeRdb::ResultSet> &resultSet,
        std::unordered_map<std::string, std::variant<int32_t, int64_t, double, std::string>> &valMap,
        const std::string &columnName, const std::string &columnType);
    void PrepareCommonColumnVal(NativeRdb::ValuesBucket &values, const std::string &columnName,
        const std::variant<int32_t, int64_t, double, std::string> &columnVal,
        const std::unordered_map<std::string, std::string> &commonColumnInfoMap) const;
    void GetQueryWhereClause(const std::string &tableName,
        const std::unordered_map<std::string, std::string> &columnInfoMap);
    void BatchQueryPhoto(std::vector<FileInfo> &fileInfos);
    void BatchNotifyPhoto(const std::vector<FileInfo> &fileInfos);
    void InsertAlbum(std::vector<AlbumInfo> &albumInfos, const std::string &tableName);
    std::vector<NativeRdb::ValuesBucket> GetInsertValues(std::vector<AlbumInfo> &albumInfos,
        const std::string &tableName);
    bool HasSameAlbum(const AlbumInfo &albumInfo, const std::string &tableName);
    void BatchQueryAlbum(std::vector<AlbumInfo> &albumInfos, const std::string &tableName);
    void BatchInsertMap(const std::vector<FileInfo> &fileInfos, int64_t &totalRowNum);
    NativeRdb::ValuesBucket GetInsertValue(const MapInfo &mapInfo) const;
    NativeRdb::ValuesBucket GetInsertValue(const AlbumInfo &albumInfo, const std::string &tableName) const;
    void CheckTableColumnStatus(std::shared_ptr<NativeRdb::RdbStore> rdbStore,
        const std::vector<std::vector<std::string>> &cloneTableList);
    bool HasColumns(const std::unordered_map<std::string, std::string> &columnInfoMap,
        const std::unordered_set<std::string> &columnSet);
    bool HasColumn(const std::unordered_map<std::string, std::string> &columnInfoMap, const std::string &columnName);
    void GetAlbumExtraQueryWhereClause(const std::string &tableName);
    bool IsReadyForRestore(const std::string &tableName);
    void PrepareEditTimeVal(NativeRdb::ValuesBucket &values, int64_t editTime, const FileInfo &fileInfo,
        const std::unordered_map<std::string, std::string> &commonColumnInfoMap) const;
    void RestoreGallery();
    bool PrepareCloudPath(const std::string &tableName, FileInfo &fileInfo);
    void RestoreMusic();
    std::vector<FileInfo> QueryFileInfos(const std::string &tableName, int32_t offset);
    bool ParseResultSet(const std::string &tableName, const std::shared_ptr<NativeRdb::ResultSet> &resultSet,
        FileInfo &fileInfo);
    void InsertAudio(std::vector<FileInfo> &fileInfos);
    int32_t QueryTotalNumberByMediaType(std::shared_ptr<NativeRdb::RdbStore> rdbStore, const std::string &tableName,
        MediaType mediaType);
    size_t StatClonetotalSize(std::shared_ptr<NativeRdb::RdbStore> mediaRdb);
    std::string GetBackupInfoByCount(int32_t photoCount, int32_t videoCount, int32_t audioCount, size_t totalSize);
    void MoveMigrateFile(std::vector<FileInfo> &fileInfos, int64_t &fileMoveCount, int64_t &videoFileMoveCount);
    void RestorePhotoBatch(int32_t offset, int32_t isRelatedToPhotoMap = 0);
    void RestoreAudioBatch(int32_t offset);
    void InsertPhotoRelated(std::vector<FileInfo> &fileInfos);
    void SetFileIdReference(const std::vector<FileInfo> &fileInfos, std::string &selection,
        std::unordered_map<int32_t, int32_t> &fileIdMap);
    int32_t QueryMapTotalNumber(const std::string &baseQuerySql);
    std::vector<MapInfo> QueryMapInfos(const std::string &tableName, const std::string &baseQuerySql, int32_t offset,
        const std::unordered_map<int32_t, int32_t> &fileIdMap, const std::unordered_map<int32_t, int32_t> &albumIdMap);
    int64_t InsertMapByTable(const std::string &tableName, const std::vector<MapInfo> &mapInfos,
        std::unordered_set<int32_t> &albumSet);
    std::vector<NativeRdb::ValuesBucket> GetInsertValues(const std::vector<MapInfo> &mapInfos);
    std::string GetQueryWhereClauseByTable(const std::string &tableName);
    void SetSpecialAttributes(const std::string &tableName, const std::shared_ptr<NativeRdb::ResultSet> &resultSet,
        FileInfo &fileInfo);
    bool IsSameFileForClone(const std::string &tableName, FileInfo &fileInfo);
    NativeRdb::ValuesBucket GetInsertValue(const AnalysisAlbumTbl &portraitAlbumInfo);
    int32_t InsertPortraitAlbumByTable(std::vector<AnalysisAlbumTbl> &analysisAlbumTbl);
    void InsertPortraitAlbum(std::vector<AnalysisAlbumTbl> &analysisAlbumTbl);
    void ParsePortraitAlbumResultSet(const std::shared_ptr<NativeRdb::ResultSet> &resultSet,
        AnalysisAlbumTbl &analysisAlbumTbl);
    std::vector<AnalysisAlbumTbl> QueryPortraitAlbumTbl(int32_t offset,
        const std::vector<std::string>& commonColumns);
    void RestoreFromGalleryPortraitAlbum();
    int32_t QueryPortraitAlbumTotalNumber(std::shared_ptr<NativeRdb::RdbStore> rdbPtr, std::string query);
    std::unordered_map<std::string, std::string> CreateImgFaceColumnFieldMap();
    void ParseImageFaceResultSet(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, ImageFaceTbl &imageFaceTbl);
    void ParseFaceTagResultSet(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, FaceTagTbl &faceTagTbl);
    NativeRdb::ValuesBucket CreateValuesBucketFromImageFaceTbl(const ImageFaceTbl& imageFaceTbl);
    void BatchInsertImageFaces(const std::vector<ImageFaceTbl>& imageFaceTbls);
    std::vector<ImageFaceTbl> ProcessImageFaceTbls(const std::vector<ImageFaceTbl>& imageFaceTbls,
        const std::vector<FileIdPair>& fileIdPairs);
    std::vector<ImageFaceTbl> QueryImageFaceTbl(int32_t offset, std::string &fileIdClause,
        const std::vector<std::string>& commonColumns);
    std::vector<PortraitAlbumDfx> QueryAllPortraitAlbum(int32_t& offset, int32_t& rowCount);
    void RecordOldPortraitAlbumDfx();
    std::unordered_set<std::string> QueryAllPortraitAlbum();
    void LogPortraitCloneDfx();
    void RestoreImageFaceInfo(std::vector<FileInfo> &fileInfos);
    NativeRdb::ValuesBucket CreateValuesBucketFromFaceTagTbl(const FaceTagTbl& faceTagTbl);
    void BatchInsertFaceTags(const std::vector<FaceTagTbl>& faceTagTbls);
    void DeleteExistingFaceTagData(const std::string& inClause);
    std::vector<FaceTagTbl> QueryFaceTagTbl(int32_t offset, const std::string& inClause);
    void RestorePortraitClusteringInfo();
    void ReportPortraitCloneStat(int32_t sceneCode);
    void AppendExtraWhereClause(std::string& whereClause, const std::string& tableName);
    void GenNewCoverUris(const std::vector<CoverUriInfo>& coverUriInfo,
        std::vector<FileInfo> &fileInfos);
    bool GetFileInfoByFileId(int32_t fileId, const std::vector<FileInfo>& fileInfos, FileInfo& outFileInfo);
    std::string GenCoverUriUpdateSql(const std::unordered_map<std::string, std::pair<std::string, int32_t>>&
        tagIdToCoverInfo, const std::unordered_map<std::string, int32_t>& oldToNewFileId,
        const std::vector<FileInfo>& fileInfos, std::vector<std::string>& tagIds);
    std::string ProcessUriAndGenNew(const std::string& tagId, const std::string& oldCoverUri,
        const std::unordered_map<std::string, int32_t>& oldToNewFileId, const std::vector<FileInfo>& fileInfos);
    int32_t MovePicture(FileInfo &fileInfo);
    int32_t MoveMovingPhotoVideo(FileInfo &fileInfo);
    int32_t MoveEditedData(FileInfo &fileInfo);
    int32_t MoveThumbnail(FileInfo &fileInfo);
    int32_t MoveThumbnailDir(FileInfo &fileInfo);
    int32_t MoveAstc(FileInfo &fileInfo);
    void InitThumbnailStatus();
    bool InitAllKvStore();
    void CloseAllKvStore();
    bool BackupKvStore();
    void GetThumbnailInsertValue(const FileInfo &fileInfo, NativeRdb::ValuesBucket &values);
    int32_t GetNoNeedMigrateCount() override;
    void GetAccountValid() override;
    int32_t GetHighlightCloudMediaCnt();
    void RestoreHighlightAlbums(bool isSyncSwitchOpen);

    template<typename T>
    static void PutIfPresent(NativeRdb::ValuesBucket& values, const std::string& columnName,
        const std::optional<T>& optionalValue);

    template<typename T>
    void PutWithDefault(NativeRdb::ValuesBucket& values, const std::string& columnName,
        const std::optional<T>& optionalValue, const T& defaultValue);

private:
    std::atomic<uint64_t> migrateDatabaseAlbumNumber_{0};
    std::atomic<uint64_t> migrateDatabaseMapNumber_{0};
    std::shared_ptr<NativeRdb::RdbStore> mediaRdb_;
    std::string filePath_;
    std::string dbPath_;
    std::unordered_map<std::string, bool> tableColumnStatusMap_;
    std::unordered_map<std::string, std::string> tableQueryWhereClauseMap_;
    std::unordered_map<std::string, std::string> tableExtraQueryWhereClauseMap_;
    std::unordered_map<std::string, std::unordered_map<int32_t, int32_t>> tableAlbumIdMap_;
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> tableCommonColumnInfoMap_;
    std::string garbagePath_;
    std::vector<CoverUriInfo> coverUriInfo_;
    std::vector<PortraitAlbumDfx> portraitAlbumDfx_;
    PhotoAlbumClone photoAlbumClone_;
    PhotosClone photosClone_;
    static constexpr int32_t INVALID_COVER_SATISFIED_STATUS = -1;
    bool hasCloneThumbnailDir_{false};
    bool isInitKvstoreSuccess_{false};
    std::shared_ptr<MediaLibraryKvStore> oldMonthKvStorePtr_ = nullptr;
    std::shared_ptr<MediaLibraryKvStore> oldYearKvStorePtr_ = nullptr;
    std::shared_ptr<MediaLibraryKvStore> newMonthKvStorePtr_ = nullptr;
    std::shared_ptr<MediaLibraryKvStore> newYearKvStorePtr_ = nullptr;
    std::vector<int> photosFailedOffsets;
    CloneRestoreGeo cloneRestoreGeo_;
    CloneRestoreHighlight cloneRestoreHighlight_;
    CloneRestoreCVAnalysis cloneRestoreCVAnalysis_;
};

template<typename T>
void CloneRestore::PutIfPresent(NativeRdb::ValuesBucket& values, const std::string& columnName,
    const std::optional<T>& optionalValue)
{
    if (optionalValue.has_value()) {
        if constexpr (std::is_same_v<std::decay_t<T>, int32_t>) {
            values.PutInt(columnName, optionalValue.value());
        } else if constexpr (std::is_same_v<std::decay_t<T>, int64_t>) {
            values.PutLong(columnName, optionalValue.value());
        } else if constexpr (std::is_same_v<std::decay_t<T>, std::string>) {
            values.PutString(columnName, optionalValue.value());
        } else if constexpr (std::is_same_v<std::decay_t<T>, double>) {
            values.PutDouble(columnName, optionalValue.value());
        }
    }
}

template<typename T>
void CloneRestore::PutWithDefault(NativeRdb::ValuesBucket& values, const std::string& columnName,
    const std::optional<T>& optionalValue, const T& defaultValue)
{
    if (optionalValue.has_value()) {
        PutIfPresent(values, columnName, optionalValue);
    } else {
        PutIfPresent(values, columnName, std::optional<T>(defaultValue));
    }
}
} // namespace Media
} // namespace OHOS

#endif  // OHOS_MEDIA_CLONE_RESTORE_H
