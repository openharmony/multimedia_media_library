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

#ifndef FOLDER_SCANNER_UTILS_H
#define FOLDER_SCANNER_UTILS_H

#include <string>

#include "asset_accurate_refresh.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_rdbstore.h"
#include "scan_rule_config.h"

namespace OHOS::Media {

class FolderScannerUtils {
public:
    static bool IsSkipCurrentFile(const std::string &fileName, const ScanRuleConfig &ruleConfig);
    static bool ShouldScanDirectory(const std::string &filePath, const ScanRuleConfig &ruleConfig);
    static int32_t BatchInsertAssets(const std::string &tableName, std::vector<NativeRdb::ValuesBucket> &values,
        std::shared_ptr<AccurateRefresh::AssetAccurateRefresh> assetRefresh);
    static void CleanNomediaInDefaultDirs(const std::string &filePath, const ScanRuleConfig &ruleConfig);
    // 扫描当前文件夹以及其父文件夹，扫描单独文件夹时使用
    static bool IsSkipDirectory(const std::string &dir, const ScanRuleConfig &ruleConfig);
    // 扫描当前文件夹是否跳过，全局扫描时使用
    static bool IsSkipCurrentDirectory(const std::string &currentDir, const ScanRuleConfig &ruleConfig);
    static bool IsCurrentOrParentDir(const std::string &dir);
};
} // namespace OHOS::Media
#endif // FOLDER_SCANNER_UTILS_H
