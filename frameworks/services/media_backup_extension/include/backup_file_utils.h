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

#ifndef BACKUP_FILE_UTILS_H
#define BACKUP_FILE_UTILS_H

#include <string>

#include "backup_const.h"
#include "metadata.h"

namespace OHOS {
namespace Media {
class FileAccessHelper {
public:
    bool GetValidPath(std::string &filePath);

private:
    bool ConvertCurrentPath(std::string &curPath, std::string &resultPath);
    std::map<std::string, std::string> pathMap = {};
    std::mutex mapMutex;
};
class BackupFileUtils {
public:
    static int32_t FillMetadata(std::unique_ptr<Metadata> &data);
    static std::string GarbleFilePath(const std::string &filePath, int32_t sceneCode, std::string cloneFilePath = "");
    static std::string GarbleFileName(const std::string &fileName);
    static int32_t CreateAssetPathById(int32_t fileId, int32_t mediaType, const std::string &extension,
        std::string &filePath);
    static std::string GetFullPathByPrefixType(PrefixType prefixType, const std::string &relativePath);
    static int32_t CreatePath(int32_t mediaType, const std::string &displayName, std::string &path);
    static int32_t PreparePath(const std::string &path);
    static int32_t MoveFile(const string &oldPath, const string &newPath, int32_t sceneCode);
    static std::string GetReplacedPathByPrefixType(PrefixType srcPrefixType, PrefixType dstPrefixType,
        const std::string &path);
    static void ModifyFile(const std::string path, int64_t modifiedTime);
    static std::string GetFileNameFromPath(const string &path);
    static std::string GetFileTitle(const string &displayName);
    static bool IsFileValid(std::string &filePath, int32_t sceneCode,
        string relativePath = "", bool hasLowQualityImage = false);
    static std::string GetDetailsPath(int32_t sceneCode, const std::string &type,
        const std::unordered_map<std::string, FailedFileInfo> &failedFiles, size_t limit);
    static std::string GetFailedFilesStr(int32_t sceneCode,
        const std::unordered_map<std::string, FailedFileInfo> &failedFiles, size_t limit);
    static std::vector<std::string> GetFailedFilesList(int32_t sceneCode,
        const std::unordered_map<std::string, FailedFileInfo> &failedFiles, size_t limit);
    static std::string GetFailedFile(int32_t sceneCode, const std::string &failedFilePath,
        const FailedFileInfo &failedFileInfo);
    static bool GetPathPosByPrefixLevel(int32_t sceneCode, const std::string &path, int32_t prefixLevel, size_t &pos);
    static bool ShouldIncludeSd(const std::string &prefix);
    static void DeleteSdDatabase(const std::string &prefix);
    static bool IsLivePhoto(const FileInfo &fileInfo);
    static bool ConvertToMovingPhoto(FileInfo &fileInfo);
    static string ConvertLowQualityPath(int32_t sceneCode, const std::string &filePath, const string &relativePath);
    static bool IsLowQualityImage(std::string &filePath, int32_t sceneCode,
        string relativePath, bool hasLowQualityImage);

private:
    static int32_t GetFileMetadata(std::unique_ptr<Metadata> &data);
    static int32_t CreateAssetRealName(int32_t fileId, int32_t mediaType, const std::string &extension,
        std::string &name);
    static std::shared_ptr<FileAccessHelper> fileAccessHelper_;
};
} // namespace Media
} // namespace OHOS

#endif  // BACKUP_FILE_UTILS_H