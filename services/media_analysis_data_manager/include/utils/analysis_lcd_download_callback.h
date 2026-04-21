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

#ifndef OHOS_ANALYSIS_LCD_DOWNLOAD_CALLBACK_H
#define OHOS_ANALYSIS_LCD_DOWNLOAD_CALLBACK_H

#include "cloud_download_callback.h"

// LCOV_EXCL_START
namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
using namespace FileManagement::CloudSync;
class LcdDownloadOperation;

class AnalysisLcdDownloadCallback : public CloudDownloadCallback {
public:
    AnalysisLcdDownloadCallback(std::shared_ptr<LcdDownloadOperation> operation) : operation_(operation) {}
    ~AnalysisLcdDownloadCallback() {}
    void OnDownloadProcess(const DownloadProgressObj& progress) override;

private:
    std::shared_ptr<LcdDownloadOperation> operation_ = nullptr;
};
} // namespace Media
} // namespace OHOS
// LCOV_EXCL_STOP
#endif // OHOS_ANALYSIS_LCD_DOWNLOAD_CALLBACK_H