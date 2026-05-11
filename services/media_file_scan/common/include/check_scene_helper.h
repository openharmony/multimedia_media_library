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
#ifndef OHOS_MEDIA_CHECK_SCENE_HELPER_H
#define OHOS_MEDIA_CHECK_SCENE_HELPER_H

#include <string>

#include "check_scene.h"
#include "file_const.h"
#include "scan_rule_config.h"

namespace OHOS::Media {
class FileParser;
class FolderParser;
struct MediaNotifyInfo;

namespace CheckSceneHelper {
CheckScene ResolveSceneByPath(const std::string &path);
const ScanRuleConfig &GetScanRuleConfig(CheckScene scene);
int32_t GetFileSourceType(CheckScene scene);
std::unique_ptr<FileParser> CreateFileParser(CheckScene scene, const std::string &path, ScanMode scanMode);
std::unique_ptr<FileParser> CreateFileParser(CheckScene scene, const MediaNotifyInfo &info, ScanMode scanMode);
std::unique_ptr<FolderParser> CreateFolderParser(CheckScene scene, const std::string &path, ScanMode scanMode);
};
} // namespace OHOS::Media

#endif // OHOS_MEDIA_CHECK_SCENE_HELPER_H