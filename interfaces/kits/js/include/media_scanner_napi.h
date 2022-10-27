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

#ifndef MEDIA_SCANNER_NAPI_H
#define MEDIA_SCANNER_NAPI_H
#include <unordered_map>

#include "medialibrary_napi_utils.h"
#include "imedia_scanner_callback.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "datashare_helper.h"

namespace OHOS {
namespace Media {
static const std::string SCANNER_HELPER_NAPI_CLASS_NAME = "ScannerInstance";

class MediaScannerNapiCallback : public IMediaScannerCallback {
public:
    int32_t OnScanFinished(const int32_t status, const std::string &uri, const std::string &path) override;
    void SetToMap(const std::string &path, const napi_ref &cbRef);

    explicit MediaScannerNapiCallback(napi_env env) : env_(env) {}
    ~MediaScannerNapiCallback() = default;

private:
    std::unordered_map<std::string, napi_ref> scannerMap_;
    napi_env env_;
};

class MediaScannerNapi {
public:
    static napi_value Init(napi_env env, napi_value exports);

    MediaScannerNapi();
    ~MediaScannerNapi();

private:
    static void MediaScannerNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_value MediaScannerNapiConstructor(napi_env env, napi_callback_info info);
    static napi_value ScanFile(napi_env env, napi_callback_info info);
    static napi_value ScanDir(napi_env env, napi_callback_info info);
    static napi_value GetMediaScannerInstance(napi_env env, napi_callback_info info);

    static napi_value NapiScanUtils(napi_env env, napi_callback_info info, const std::string &scanType);
    static void DataShareScanBoardcast(const std::string &event);
    std::shared_ptr<MediaScannerNapiCallback> mediaScannerNapiCallbackObj_;

    napi_env env_;

    static thread_local napi_ref sConstructor_;
};
} // namespace Media
} // namespace OHOS
#endif /* MEDIA_SCANNER_NAPI_H */
