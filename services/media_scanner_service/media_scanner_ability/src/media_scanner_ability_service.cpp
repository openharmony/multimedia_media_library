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

#include "media_scanner_ability_service.h"
#include "media_log.h"

using namespace std;
namespace OHOS {
namespace Media {
int32_t MediaScannerAbilityService::ScanDirService(string &scanDirPath, const sptr<IRemoteObject> &callback)
{
    return MediaScanner::GetMediaScannerInstance()->ScanDir(scanDirPath, callback);
}

int32_t MediaScannerAbilityService::ScanFileService(string &scanFilePath, const sptr<IRemoteObject> &callback)
{
    return MediaScanner::GetMediaScannerInstance()->ScanFile(scanFilePath, callback);
}

bool MediaScannerAbilityService::IsScannerRunning()
{
    return MediaScanner::GetMediaScannerInstance()->IsScannerRunning();
}
} // namespace Media
} // namespace OHOS
