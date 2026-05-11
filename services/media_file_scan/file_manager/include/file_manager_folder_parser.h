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

#ifndef OHOS_FILE_MANAGER_FOLDER_PARSER_H
#define OHOS_FILE_MANAGER_FOLDER_PARSER_H

#include "folder_parser.h"

namespace OHOS {
namespace Media {

using namespace std;

class FileManagerFolderParser : public FolderParser {
public:
    FileManagerFolderParser(const std::string &storagePath, ScanMode scanType = ScanMode::INCREMENT);
    ~FileManagerFolderParser() = default;

private:
    int32_t GetConvertedLpath(const std::string &data, std::string &lpath) override;
    bool IsFolderSkip() override;
    int32_t GetAlbumName(CommonAlbumInfo &commonAlbumInfo) override;
    void GetUniqueAlbumName(std::string &albumName) override;
};
} // namespace Media
} // namespace OHOS

#endif  // OHOS_FILE_MANAGER_FOLDER_PARSER_H