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
const FILTER_MEDIA_TYPE_ALL = 'FILTER_MEDIA_TYPE_ALL';
const FILTER_MEDIA_TYPE_IMAGE = 'FILTER_MEDIA_TYPE_IMAGE';
const FILTER_MEDIA_TYPE_VIDEO = 'FILTER_MEDIA_TYPE_VIDEO';

@Component
export struct PhotoPickerComponent {
  pickerOptions?: PickerOptions | undefined;
  onSelect?: (uri: string) => void;
  onDeselect?: (uri: string) => void;
  @ObjectLink @Watch('onChanged') pickerController: PickerController;
  private proxy: UIExtensionProxy | undefined;

  private onChanged(): void {
    console.info('PhotoPickerComponent onchanged' + this.pickerController?.selectedUris?.toString);
    if (this.proxy) {
      this.proxy.send({"selectUris": this.pickerController?.selectedUris});
    }
  }

  build() {
    Row() {
      Column() {
        UIExtensionComponent({
          parameters: {
            "ability.want.params.uiExtensionTargetType":"photoPicker",
            uri: "multipleselect",
            filterMediaType: this.convertMIMETypeToFilterType(this.pickerOptions?.MIMEType),
            maxSelectNumber: this.pickerOptions?.maxSelectNumber as number,
            isPhotoTakingSupported: this.pickerOptions?.isPhotoTakingSupported as boolean,
            isEditSupported: false,
            recommendationOptions: this.pickerOptions?.recommendationOptions as photoAccessHelper.RecommendationOptions,
            preselectedUri: this.pickerOptions?.preselectedUris as Array<string>,
            isFromPickerView: true,
            isNeedActionBar: false,
            isNeedSelectBar: false,
            isSearchSupported: this.pickerOptions?.isSearchSupported as boolean,
          }
        }).height('100%').width('100%').onRemoteReady((proxy) => {
          this.proxy = proxy;
        }).onReceive((data) => {
          let wantParam: Record<string, Object> = data as Record<string, Object>;
          let dataType = wantParam['dataType'] as string;
          if (dataType === 'selectOrDeselect') {
            let isSelect: boolean = wantParam['isSelect'] as boolean;
            if (isSelect) {
              if (this.onSelect) {
                this.onSelect(wantParam['select-item-list'] as string)
              }
            } else {
              if (this.onDeselect) {
                this.onDeselect(wantParam['select-item-list'] as string)
              }
            }
          } else {
            console.info('PhotoPickerComponent onReceive: other case');
          }
          console.info('PhotoPickerComponent onReceive' + JSON.stringify(wantParam));
        }).onResult((data) => {
          console.info('PhotoPickerComponent onResult');
        }).onError(() => {
          console.info('PhotoPickerComponent onError');
        }).onRelease((data) => {
          console.info('PhotoPickerComponent onRelease');
        });
      }
      .width('100%')
    }
    .height('100%')
  }

  private convertMIMETypeToFilterType(mimeType: photoAccessHelper.PhotoViewMIMETypes): string {
    let filterType: string;
    if (mimeType === photoAccessHelper.PhotoViewMIMETypes.IMAGE_TYPE) {
      filterType = FILTER_MEDIA_TYPE_IMAGE;
    } else if (mimeType === photoAccessHelper.PhotoViewMIMETypes.VIDEO_TYPE) {
      filterType = FILTER_MEDIA_TYPE_VIDEO;
    } else {
      filterType = FILTER_MEDIA_TYPE_ALL;
    }
    console.info('PhotoPickerComponent convertMIMETypeToFilterType' + JSON.stringify(filterType));
    return filterType;
  }
}

@Observed
export class PickerController {
  selectedUris?: Array<string>;

  setData(type: DataType, data: Object) {
    if (!data) {
      return;
    }
    if (type === DataType.SET_SELECTED_URIS) {
      if (data instanceof Array) {
        let uriLists: Array<string> = data as Array<string>;
        if (uriLists) {
          this.selectedUris = [...uriLists];
          console.info('PhotoPickerComponent setData' + JSON.stringify(this.selectedUris));
        }
      }
    }
  }
}

export class PickerOptions extends photoAccessHelper.BaseSelectOptions {
  checkBoxColor?: string;
  backgroundColor?: string;
  isRepeatSelectSupported?: boolean;
}

export enum DataType {
  SET_SELECTED_URIS = 1
}