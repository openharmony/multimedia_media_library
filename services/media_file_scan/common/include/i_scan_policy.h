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
#ifndef OHOS_MEDIA_I_SCAN_POLICY_H
#define OHOS_MEDIA_I_SCAN_POLICY_H

#include <string>

#include "check_scene.h"
#include "file_const.h"

namespace OHOS::Media {
class FileScanner;

class IScanPolicy {
public:
    virtual ~IScanPolicy() = default;

    virtual CheckScene GetScene() const = 0;
    virtual void OnScanFinished(bool isFirstScanner) = 0;
    virtual std::unique_ptr<FileScanner> CreateFileScanner(ScanMode scanMode) = 0;
};
} // namespace OHOS::Media

#endif // OHOS_MEDIA_I_SCAN_POLICY_H