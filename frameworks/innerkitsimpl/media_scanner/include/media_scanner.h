/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef MEDIA_SCANNER_H
#define MEDIA_SCANNER_H

#include <algorithm>
#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <ftw.h>
#include <iostream>
#include <iterator>
#include <limits.h>
#include <securec.h>
#include <stdlib.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "media_lib_service_const.h"
#include "media_scan_executor.h"
#include "media_scanner_const.h"
#include "media_scanner_db.h"
#include "metadata.h"
#include "metadata_extractor.h"
#include "scanner_utils.h"
#include "imedia_scanner_operation_callback.h"
#include "iremote_object.h"
#include "mediadata_helper.h"
#include "napi_remote_object.h"
#include "mediadata_stub_impl.h"
#include "mediadata_proxy.h"

#define FREE_MEMORY_AND_SET_NULL(fName)      \
    do {                                     \
        free(fName);                         \
        fName = nullptr;                     \
    } while (0)

namespace OHOS {
namespace Media {
/**
 * Media Scanner class for scanning files and folders in MediaLibrary Database
 * and updating the metadata for each media file
 *
 * @since 1.0
 * @version 1.0
 */
class MediaScanner {
public:
    static MediaScanner *GetMediaScannerInstance();
    int32_t ScanFile(std::string &path, const sptr<IRemoteObject> &callback);
    int32_t ScanDir(std::string &path, const sptr<IRemoteObject> &callback);
    bool IsScannerRunning();
    void SetAbilityContext(const std::shared_ptr<OHOS::AppExecFwk::Context> &context);
    void ReleaseAbilityHelper();

private:
    MediaScanner();
    ~MediaScanner();

    static void ScanQueueCB(ScanRequest sr);
    std::unique_ptr<Metadata> GetFileMetadata(const std::string &path, const int32_t parentId);
    std::vector<std::string> GetSupportedMimeTypes();

    void InitSkipList();
    void CheckIfFolderScanCompleted(const int32_t reqId);
    void CleanupDirectory(const std::string &path);
    void ExecuteScannerClientCallback(int32_t reqId, int32_t status, const std::string &uri, const string &path);
    void StoreCallbackObjInMap(int32_t reqId, sptr<IMediaScannerOperationCallback> &callback);

    bool CheckSkipScanList(const std::string &path);
    bool IsFileScanned(Metadata &fileMetadata);
    bool IsDirHidden(const std::string &path);
    bool IsDirHiddenRecursive(const std::string &path);
    bool InitScanner(const std::shared_ptr<OHOS::AppExecFwk::Context> &context);

    int32_t VisitFile(const Metadata &fileMetadata);
    int32_t WalkFileTree(const std::string &path, int32_t parentId);
    int32_t ScanFileContent(const std::string &path, const int32_t parentId);
    int32_t ScanFileInternal(const std::string &path);
    int32_t ScanDirInternal(const std::string &path);
    int32_t StartBatchProcessingToDB();
    int32_t StartBatchProcessIfFull();
    int32_t BatchUpdateRequest(Metadata &fileMetadata);
    int32_t RetrieveMetadata(Metadata &fileMetadata);
    int32_t GetAvailableRequestId();
    int32_t InsertAlbumInfo(std::string &albumPath, int32_t parentId, string &albumName);

    bool isScannerInitDone_;
    MediaScanExecutor scanExector_;
    MetadataExtractor metadataExtract_;
    std::unordered_map<std::string, Metadata> albumMap_;

    std::string mediaUri_;
    std::vector<size_t> skipList_;
    std::unordered_set<int32_t> scannedIds_;
    std::vector<Metadata> batchUpdate_;
    std::unique_ptr<MediaScannerDb> mediaScannerDb_;
    std::shared_ptr<AppExecFwk::MediaDataHelper> rdbhelper_;
    std::shared_ptr<OHOS::AppExecFwk::Context> abilityContext_;
    std::unordered_map<int32_t, sptr<IMediaScannerOperationCallback>> scanResultCbMap_;
};
} // namespace Media
} // namespace OHOS

#endif // MEDIA_SCANNER_H
