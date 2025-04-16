/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

import photoAccessHelper from '@ohos.file.photoAccessHelper';
import { BaseItemInfo } from '@ohos.file.PhotoPickerComponent';

const FILTER_MEDIA_TYPE_ALL = 'FILTER_MEDIA_TYPE_ALL';
const FILTER_MEDIA_TYPE_IMAGE = 'FILTER_MEDIA_TYPE_IMAGE';
const FILTER_MEDIA_TYPE_VIDEO = 'FILTER_MEDIA_TYPE_VIDEO';
const FILTER_MEDIA_TYPE_IMAGE_MOVING_PHOTO = 'FILTER_MEDIA_TYPE_IMAGE_MOVING_PHOTO';

@Component
export struct RecentPhotoComponent {
  public recentPhotoOptions: RecentPhotoOptions | undefined;
  public onRecentPhotoCheckResult?: RecentPhotoCheckResultCallback;
  public onRecentPhotoClick?: RecentPhotoClickCallback;
  public onRecentPhotoCheckInfo?: RecentPhotoCheckInfoCallback;

  build() {
    Row() {
      Column() {
        SecurityUIExtensionComponent({
          bundleName: 'com.ohos.photos',
          abilityName: 'RecentUIExtensionAbility',
          parameters: {
            'ability.want.params.uiExtensionType': 'recentPhoto',
            filterMediaType: this.convertMIMETypeToFilterType(this.recentPhotoOptions?.MIMEType),
            period: this.recentPhotoOptions?.period as number,
            photoSource: this.recentPhotoOptions?.photoSource as PhotoSource,
            isFromPickerView: true,
            isRecentPhotoCheckResultSet: this.onRecentPhotoCheckResult ? true : false
          }
        })
          .height('100%')
          .width('100%')
          .onRemoteReady(() => {
            console.info('RecentPhotoComponent onRemoteReady');
          })
          .onReceive((data) => {
            let wantParam: Record<string, Object> = data as Record<string, Object>;
            this.handleOnReceive(wantParam);
          })
          .onError(() => {
            console.info('RecentPhotoComponent onError');
          })
      }
      .width('100%')
    }
    .height('100%')
  }

  private handleOnReceive(wantParam: Record<string, Object>): void {
    console.info('RecentPhotoComponent OnReceive:' + JSON.stringify(wantParam));
    let dataType: string = wantParam['dataType'] as string;
    if (dataType === 'checkResult') {
      if (this.onRecentPhotoCheckResult) {
        this.onRecentPhotoCheckResult(wantParam['isExist'] as boolean);
      }
    } else if (dataType === 'select') {
      if (this.onRecentPhotoClick) {
        let baseItemInfo: BaseItemInfo = new BaseItemInfo();
        baseItemInfo.uri = wantParam['uri'] as string;
        baseItemInfo.mimeType = wantParam['mimeType'] as string;
        baseItemInfo.width = wantParam['width'] as number;
        baseItemInfo.height = wantParam['height'] as number;
        baseItemInfo.size = wantParam['size'] as number;
        baseItemInfo.duration = wantParam['duration'] as number;
        this.onRecentPhotoClick(baseItemInfo);
      } else {
        console.warn('RecentPhotoComponent onReceive data type is invalid.');
      }
    } else if (dataType === 'checkInfo') {
      if (this.onRecentPhotoCheckInfo) {
        let info: RecentPhotoInfo = new RecentPhotoInfo();
        info.identifier = wantParam.identifier as string;
        info.dateTaken = wantParam.dateTaken as number;
        this.onRecentPhotoCheckInfo(wantParam.isExist as boolean, info);
      }
    }
  }

  private convertMIMETypeToFilterType(mimeType: photoAccessHelper.PhotoViewMIMETypes | undefined): string {
    let filterType: string;
    if (mimeType === photoAccessHelper.PhotoViewMIMETypes.IMAGE_TYPE) {
      filterType = FILTER_MEDIA_TYPE_IMAGE;
    } else if (mimeType === photoAccessHelper.PhotoViewMIMETypes.VIDEO_TYPE) {
      filterType = FILTER_MEDIA_TYPE_VIDEO;
    } else if (mimeType === photoAccessHelper.PhotoViewMIMETypes.MOVING_PHOTO_IMAGE_TYPE) {
      filterType = FILTER_MEDIA_TYPE_IMAGE_MOVING_PHOTO;
    } else {
      filterType = FILTER_MEDIA_TYPE_ALL;
    }
    console.info('RecentPhotoComponent convertMIMETypeToFilterType: ' + JSON.stringify(filterType));
    return filterType;
  }
}

export type RecentPhotoCheckResultCallback = (recentPhotoExists: boolean) => void;

export type RecentPhotoClickCallback = (recentPhotoInfo: BaseItemInfo) => boolean;

export type RecentPhotoCheckInfoCallback = (recentPhotoExists: boolean, info: RecentPhotoInfo) => void;

export class RecentPhotoOptions {
  period?: number;
  MIMEType?: photoAccessHelper.PhotoViewMIMETypes;
  photoSource?: PhotoSource
}

export class RecentPhotoInfo {
  dateTaken?: number;
  identifier?: string;
}

export enum PhotoSource {
  ALL = 0,
  CAMERA = 1,
  SCREENSHOT = 2
}
