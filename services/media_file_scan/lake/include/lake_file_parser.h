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
 
#ifndef LAKE_FILE_PARSER_H
#define LAKE_FILE_PARSER_H

#include "file_parser.h"

namespace OHOS::Media {
class LakeFileParser : public FileParser {
public:
    LakeFileParser(const std::string &path, ScanMode scanMode = ScanMode::INCREMENT);
    LakeFileParser(const MediaNotifyInfo &info, ScanMode scanMode = ScanMode::INCREMENT);
    ~LakeFileParser() = default;

    FileUpdateType GetFileUpdateType() override;
    void SetCloudPath() override;

private:
    void SetSubtypeFromMetadata(std::unique_ptr<Metadata> &data) override;

    int32_t GetUniqueId();

    static std::atomic<uint32_t> imageNumber_;
    static std::atomic<uint32_t> videoNumber_;
};
} // namespace OHOS::Media
#endif // LAKE_FILE_PARSER_H