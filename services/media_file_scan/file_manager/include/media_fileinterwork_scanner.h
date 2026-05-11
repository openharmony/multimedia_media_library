/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_INTERWORKING_SCANNER_H
#define INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_INTERWORKING_SCANNER_H

#include <string>

#include "asset_accurate_refresh.h"
#include "metadata.h"
#include "medialibrary_rdbstore.h"
#ifdef MEDIALIBRARY_FEATURE_CUSTOM_RESTORE
#include "photo_custom_restore_operation.h"
#endif

namespace OHOS::Media {

#ifndef MEDIALIBRARY_FEATURE_CUSTOM_RESTORE
struct FileInfo {
    std::string originFilePath;
    std::string filePath;
    std::string fileName;
    std::string displayName;
    std::string title;
    std::string extension;
    MediaType mediaType;
    int32_t size;
    int32_t orientation;
    bool isLivePhoto;
    int32_t fileId;
    std::string mimeType;
    int32_t subtype;
    int32_t movingPhotoEffectMode;
    std::string frontCamera;
    std::string shootingMode;
    int32_t albumId;
};

struct UniqueNumber {
    int32_t imageTotalNumber = 0;
    int32_t videoTotalNumber = 0;
    int32_t imageCurrentNumber = 0;
    int32_t videoCurrentNumber = 0;

    UniqueNumber operator+(const UniqueNumber &other) const
    {
        UniqueNumber result;
        result.imageTotalNumber = this->imageTotalNumber + other.imageTotalNumber;
        result.videoTotalNumber = this->videoTotalNumber + other.videoTotalNumber;
        result.imageCurrentNumber = this->imageCurrentNumber + other.imageCurrentNumber;
        result.videoCurrentNumber = this->videoCurrentNumber + other.videoCurrentNumber;
        return result;
    }

    void clear()
    {
        imageTotalNumber = 0;
        videoTotalNumber = 0;
        imageCurrentNumber = 0;
        videoCurrentNumber = 0;
    }
};
#endif

class MediaFileInterworkScanner {
public:
    EXPORT virtual ~MediaFileInterworkScanner() = default;
    EXPORT static MediaFileInterworkScanner* GetInstance();
    EXPORT void ScanFileManager();
private:
    MediaFileInterworkScanner() = default;
    std::mutex asyncTaskMutex_;  // 异步任务互斥锁
    std::atomic<bool> isAsyncTaskRunning_{false};  // 异步任务运行状态标志
    std::thread taskThread_;
    map<std::string, int32_t> albumCache_;

    int32_t GetTaskStatus();
    int32_t SetTaskStatus(int32_t status);
    bool CheckSystemConditions();
    int32_t ScanDirectory(const std::string &path, std::vector<std::string> &files);
    bool IsImageOrVideoFile(const std::string &filePath);
    bool IsValidFileName(const std::string &fileName);
    bool ShouldSkipDirectory(const std::string &dirPath);
    int32_t ExecutePhaseOne();

    int32_t GetFileMetadata(std::unique_ptr<Metadata> &data);
    void SetTimeInfo(const std::unique_ptr<Metadata> &data, FileInfo &info, NativeRdb::ValuesBucket &value);
    int32_t InsertFileBatch(const std::vector<std::string> &files);
    int32_t InsertOrUpdateAlbum(const std::string &albumPath, int32_t &albumId);
    int32_t CleanTabFileOptTable();
    int32_t FillMetadata(const FileInfo &fileInfo, std::unique_ptr<Metadata> &data);
    NativeRdb::ValuesBucket GetInsertValue(FileInfo &fileInfo);
    int32_t UpdateUniqueNumber(UniqueNumber &uniqueNumber);
    vector<FileInfo> SetDestinationPath(vector<FileInfo> &restoreFiles, UniqueNumber &uniqueNumber);
    vector<FileInfo> GetFileInfos(const std::vector<std::string> &filePathVector, UniqueNumber &uniqueNumber);
    std::vector<string> GetPhotosNotExists(const std::shared_ptr<MediaLibraryRdbStore> rdbStore,
        const std::vector<std::string> &files);
    int32_t SetRestoreFileAlbumId(std::vector<FileInfo> &destRestoreFiles);
    std::shared_ptr<NativeRdb::ResultSet> GetOptFile(const std::shared_ptr<MediaLibraryRdbStore> rdbStore);
    int32_t UpdateOptStatus(const std::shared_ptr<MediaLibraryRdbStore> rdbStore, std::vector<std::string> fileBatch);
    int32_t BatchUpdateTimePending(const vector<FileInfo> &restoreFiles,
        AccurateRefresh::AssetAccurateRefresh &assetRefresh);
    int32_t ProcessPhaseTwoRecords();

    int32_t BatchInsert(std::vector<FileInfo> &files);
    int32_t HandlePhotosRestore(const std::vector<std::string> &files);
    int32_t ExecutePhaseTwo();
};
} // namespace OHOS::Media
#endif // INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_INTERWORKING_SCANNER_H