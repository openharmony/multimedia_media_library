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

#ifndef INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_ALBUM_ORDER_NAPI_H_
#define INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_ALBUM_ORDER_NAPI_H_

#include "album_order.h"

#include "datashare_values_bucket.h"
#include "fetch_result.h"
#include "file_asset.h"
#include "napi_error.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
class AlbumOrderNapi {
public:
    EXPORT AlbumOrderNapi();
    EXPORT ~AlbumOrderNapi();

    EXPORT static napi_value PhotoAccessInit(napi_env env, napi_value exports);
    EXPORT static napi_value CreateAlbumOrderNapi(napi_env env, std::unique_ptr<AlbumOrder> &albumData);
    EXPORT static napi_value CreateAlbumOrderNapi(napi_env env, std::shared_ptr<AlbumOrder> &albumData);

    int32_t GetAlbumId() const;
    int32_t GetAlbumOrder() const;
    int32_t GetOrderSection() const;
    int32_t GetOrderType() const;
    int32_t GetOrderStatus() const;
    
    std::shared_ptr<AlbumOrder> GetAlbumOrderInstance() const;

private:
    EXPORT void SetAlbumOrderNapiProperties();
    EXPORT static napi_value AlbumOrderNapiConstructor(napi_env env, napi_callback_info info);
    EXPORT static void AlbumOrderNapiDestructor(napi_env env, void *nativeObject, void *finalizeHint);

    EXPORT static napi_value JSGetAlbumId(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSSetAlbumId(napi_env env, napi_callback_info info);

    EXPORT static napi_value JSGetAlbumOrder(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSSetAlbumOrder(napi_env env, napi_callback_info info);

    EXPORT static napi_value JSGetOrderSection(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSSetOrderSection(napi_env env, napi_callback_info info);

    EXPORT static napi_value JSGetOrderType(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSSetOrderType(napi_env env, napi_callback_info info);

    EXPORT static napi_value JSGetOrderStatus(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSSetOrderStatus(napi_env env, napi_callback_info info);

    napi_env env_;
    std::shared_ptr<AlbumOrder> albumOrderPtr;
    static thread_local AlbumOrder *pOrderData_;
    static thread_local napi_ref constructor_;
    static thread_local napi_ref photoAccessConstructor_;
    static std::mutex mutex_;
};
} // namespace Media
} // namespace OHOS

#endif  // INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_PHOTO_ALBUM_NAPI_H_