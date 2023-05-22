#include "exiv2/image.hpp"
#include "exiv2/error.hpp"
#include "ruby.h"
#include "ruby/encoding.h"

static const rb_encoding *UTF_8 = rb_enc_find("UTF-8");

static VALUE to_ruby_string(const std::string& string, const rb_encoding *encoding = UTF_8) {
  return rb_enc_str_new(string.data(), string.length(), encoding);
}

// Create a C++ std::string from a Ruby string.
static std::string to_std_string(VALUE string) {
  string = StringValue(string); // Convert the Ruby object to a string if it isn't one.
  return std::string(RSTRING_PTR(string), RSTRING_LEN(string));
}

// Create a C++ std::string from a Ruby object.
static std::string value_to_std_string(VALUE obj) {
  VALUE string = rb_funcall(obj, rb_intern("to_s"), 0);
  return std::string(RSTRING_PTR(string), RSTRING_LEN(string));
}

// Shared method for implementing each on XmpData, IptcData and ExifData.
template <class T>
static VALUE metadata_each(VALUE self, const rb_encoding *encoding = UTF_8) {
  T* data;
  Data_Get_Struct(self, T, data);

  for (typename T::iterator it = data->begin(); it != data->end(); it++) {
    int n = it->count();
    if (n == 0) continue;

    const Exiv2::Value &val = it->value();

    VALUE key = to_ruby_string(it->key());
    VALUE value = 0;

    switch (it->typeId()) {
      case Exiv2::unsignedByte:
      case Exiv2::unsignedShort:
      case Exiv2::unsignedLong:
      case Exiv2::unsignedLongLong:
      case Exiv2::tiffIfd:
      case Exiv2::tiffIfd8: {
        value = ULL2NUM(val.toLong(0));
        break;
      }

      case Exiv2::signedByte:
      case Exiv2::signedShort:
      case Exiv2::signedLong:
      case Exiv2::signedLongLong: {
        value = LL2NUM(val.toLong(0));
        break;
      }

      case Exiv2::tiffFloat:
      case Exiv2::tiffDouble: {
        value = rb_float_new((double) val.toFloat(0));
        break;
      }

      case Exiv2::date: {
        value = rb_funcall(rb_path2class("Date"), rb_intern("parse"), 1, to_ruby_string(val.toString(0)));
        break;
      }

      case Exiv2::time: {
        value = rb_funcall(rb_path2class("Time"), rb_intern("parse"), 1, to_ruby_string(val.toString(0)));
        break;
      }

      case Exiv2::unsignedRational: {
        Exiv2::Rational rational = val.toRational(0);
        value = rb_funcall(rb_mKernel, rb_intern("Rational"), 2, UINT2NUM(rational.first), UINT2NUM(rational.second));
        break;
      }

      case Exiv2::signedRational: {
        Exiv2::Rational rational = val.toRational(0);
        value = rb_funcall(rb_mKernel, rb_intern("Rational"), 2, INT2NUM(rational.first), INT2NUM(rational.second));
        break;
      }

      // TODO: this doesn't roundtrip yet
      case Exiv2::langAlt: {
        Exiv2::LangAltValue::ValueType values = static_cast<const Exiv2::LangAltValue &>(val).value_;
        Exiv2::LangAltValue::ValueType::iterator first = values.begin();

        if (n == 1 && first->first == "x-default") {
          value = to_ruby_string(first->second, encoding);
        } else {
          value = rb_hash_new_capa(n);

          for (Exiv2::LangAltValue::ValueType::iterator itv = values.begin(); itv != values.end(); itv++) {
            VALUE lang = to_ruby_string(itv->first, encoding);
            VALUE item = to_ruby_string(itv->second, encoding);
            rb_hash_aset(value, lang, item);
          }
        }
        break;
     }

      case Exiv2::xmpBag:
      case Exiv2::xmpSeq: {
        value = rb_ary_new_capa(n);

        for (int i = 0; i < n; i++) {
          VALUE item = to_ruby_string(val.toString(i), encoding);
          rb_ary_push(value, item);
        }
        break;
      }

      case Exiv2::undefined: {
        value = to_ruby_string(val.toString(), encoding);
        break;
      }

      default: {
        value = to_ruby_string(val.toString(0), encoding);
        break;
      }
    }

    if (value)
      rb_yield(rb_ary_new3(2, key, value));
  }

  return Qnil;
}

typedef VALUE (*Method)(...);

static VALUE exiv2_module;

static VALUE basic_error_class;

static VALUE image_class;
static void image_free(Exiv2::Image* image);
static VALUE image_read_metadata(VALUE self);
static VALUE image_write_metadata(VALUE self);
static VALUE image_iptc_data(VALUE self);
static VALUE image_xmp_data(VALUE self);
static VALUE image_exif_data(VALUE self);
static VALUE image_copy_to_image(VALUE self, VALUE other);
static VALUE image_clear(VALUE self);

static VALUE image_factory_class;
static VALUE image_factory_open(VALUE klass, VALUE path);

static VALUE exif_data_class;
static VALUE exif_data_each(VALUE self);
static VALUE exif_data_add(VALUE self, VALUE key, VALUE value);
static VALUE exif_data_delete(VALUE self, VALUE key);
static VALUE exif_data_clear(VALUE self);

static VALUE iptc_data_class;
static VALUE iptc_data_each(VALUE self);
static VALUE iptc_data_add(VALUE self, VALUE key, VALUE value);
static VALUE iptc_data_delete(VALUE self, VALUE key);
static VALUE iptc_data_clear(VALUE self);

static VALUE xmp_data_class;
static VALUE xmp_data_each(VALUE self);
static VALUE xmp_data_add(VALUE self, VALUE key, VALUE value);
static VALUE xmp_data_delete(VALUE self, VALUE key);
static VALUE xmp_data_clear(VALUE self);

extern "C" void Init_exiv2() {
  VALUE enumerable_module = rb_const_get(rb_cObject, rb_intern("Enumerable"));

  exiv2_module = rb_define_module("Exiv2");

  basic_error_class = rb_define_class_under(exiv2_module, "BasicError", rb_eRuntimeError);

  image_class = rb_define_class_under(exiv2_module, "Image", rb_cObject);
  rb_undef_alloc_func(image_class);
  rb_define_method(image_class, "read_metadata", (Method)image_read_metadata, 0);
  rb_define_method(image_class, "write_metadata", (Method)image_write_metadata, 0);
  rb_define_method(image_class, "iptc_data", (Method)image_iptc_data, 0);
  rb_define_method(image_class, "xmp_data", (Method)image_xmp_data, 0);
  rb_define_method(image_class, "exif_data", (Method)image_exif_data, 0);
  rb_define_method(image_class, "copy_to_image", (Method)image_copy_to_image, 1);
  rb_define_method(image_class, "clear", (Method)image_clear, 0);

  image_factory_class = rb_define_class_under(exiv2_module, "ImageFactory", rb_cObject);
  rb_define_singleton_method(image_factory_class, "open", (Method)image_factory_open, 1);

  exif_data_class = rb_define_class_under(exiv2_module, "ExifData", rb_cObject);
  rb_undef_alloc_func(exif_data_class);
  rb_include_module(exif_data_class, enumerable_module);
  rb_define_method(exif_data_class, "each", (Method)exif_data_each, 0);
  rb_define_method(exif_data_class, "add", (Method)exif_data_add, 2);
  rb_define_method(exif_data_class, "delete", (Method)exif_data_delete, 1);
  rb_define_method(exif_data_class, "clear", (Method)exif_data_clear, 0);

  iptc_data_class = rb_define_class_under(exiv2_module, "IptcData", rb_cObject);
  rb_undef_alloc_func(iptc_data_class);
  rb_include_module(iptc_data_class, enumerable_module);
  rb_define_method(iptc_data_class, "each", (Method)iptc_data_each, 0);
  rb_define_method(iptc_data_class, "add", (Method)iptc_data_add, 2);
  rb_define_method(iptc_data_class, "delete", (Method)iptc_data_delete, 1);
  rb_define_method(iptc_data_class, "clear", (Method)iptc_data_clear, 0);

  xmp_data_class = rb_define_class_under(exiv2_module, "XmpData", rb_cObject);
  rb_undef_alloc_func(xmp_data_class);
  rb_include_module(xmp_data_class, enumerable_module);
  rb_define_method(xmp_data_class, "each", (Method)xmp_data_each, 0);
  rb_define_method(xmp_data_class, "add", (Method)xmp_data_add, 2);
  rb_define_method(xmp_data_class, "delete", (Method)xmp_data_delete, 1);
  rb_define_method(xmp_data_class, "clear", (Method)xmp_data_clear, 0);
}


// Exiv2::Image Methods

static void image_free(Exiv2::Image* image) {
  delete image;
}

static VALUE image_read_metadata(VALUE self) {
  Exiv2::Image* image;
  Data_Get_Struct(self, Exiv2::Image, image);

  try {
    image->readMetadata();
  }
  catch (Exiv2::BasicError<char> error) {
    rb_raise(basic_error_class, "%s", error.what());
  }

  return Qnil;
}

static VALUE image_write_metadata(VALUE self) {
  Exiv2::Image* image;
  Data_Get_Struct(self, Exiv2::Image, image);

  try {
    image->writeMetadata();
  }
  catch (Exiv2::BasicError<char> error) {
    rb_raise(basic_error_class, "%s", error.what());
  }

  return Qnil;
}

static VALUE image_exif_data(VALUE self) {
  Exiv2::Image* image;
  Data_Get_Struct(self, Exiv2::Image, image);

  VALUE exif_data = Data_Wrap_Struct(exif_data_class, 0, 0, &image->exifData());
  rb_iv_set(exif_data, "@image", self);  // Make sure we don't GC the image until there are no references to the EXIF data left.

  return exif_data;
}

static VALUE image_iptc_data(VALUE self) {
  Exiv2::Image* image;
  Data_Get_Struct(self, Exiv2::Image, image);

  VALUE iptc_data = Data_Wrap_Struct(iptc_data_class, 0, 0, &image->iptcData());
  rb_iv_set(iptc_data, "@image", self);  // Make sure we don't GC the image until there are no references to the IPTC data left.

  return iptc_data;
}


static VALUE image_xmp_data(VALUE self) {
  Exiv2::Image* image;
  Data_Get_Struct(self, Exiv2::Image, image);

  VALUE xmp_data = Data_Wrap_Struct(xmp_data_class, 0, 0, &image->xmpData());
  rb_iv_set(xmp_data, "@image", self);  // Make sure we don't GC the image until there are no references to the XMP data left.

  return xmp_data;
}

static VALUE image_copy_to_image(VALUE self, VALUE other) {
  Exiv2::Image *image, *other_image;
  Data_Get_Struct(self,  Exiv2::Image, image);
  Data_Get_Struct(other, Exiv2::Image, other_image);

  const Exiv2::Image &image_ref = *image;
  other_image->setMetadata(image_ref);

  return Qtrue;
}

static VALUE image_clear(VALUE self) {
  Exiv2::Image* image;
  Data_Get_Struct(self, Exiv2::Image, image);

  image->exifData().clear();
  image->iptcData().clear();
  image->xmpData().clear();

  return Qtrue;
}

// Exiv2::ImageFactory methods

static VALUE image_factory_open(VALUE klass, VALUE path) {
  Exiv2::Image* image;

  try {
    Exiv2::Image::AutoPtr image_auto_ptr = Exiv2::ImageFactory::open(to_std_string(path));
    image = image_auto_ptr.release(); // Release the AutoPtr, so we can keep the image around.
  }
  catch (Exiv2::BasicError<char> error) {
    rb_raise(basic_error_class, "%s", error.what());
  }

  return Data_Wrap_Struct(image_class, 0, image_free, image);
}


// Exiv2::ExifData methods

static VALUE exif_data_each(VALUE self) {
  return metadata_each<Exiv2::ExifData>(self);
}

static VALUE exif_data_add(VALUE self, VALUE key, VALUE value) {
  Exiv2::ExifData* data;
  Data_Get_Struct(self, Exiv2::ExifData, data);

  Exiv2::ExifKey exifKey = Exiv2::ExifKey(to_std_string(key));

#if EXIV2_MAJOR_VERSION <= 0 && EXIV2_MINOR_VERSION <= 20
  Exiv2::TypeId typeId = Exiv2::ExifTags::tagType(exifKey.tag(), exifKey.ifdId());
#else
  Exiv2::TypeId typeId = exifKey.defaultTypeId();
#endif

  Exiv2::Value::AutoPtr v = Exiv2::Value::create(typeId);
  v->read(value_to_std_string(value));

  data->add(exifKey, v.get());
  return Qtrue;
}

static VALUE exif_data_delete(VALUE self, VALUE key) {
  Exiv2::ExifData* data;
  Data_Get_Struct(self, Exiv2::ExifData, data);

  Exiv2::ExifKey exifKey = Exiv2::ExifKey(to_std_string(key));
  Exiv2::ExifData::iterator pos = data->findKey(exifKey);
  if(pos == data->end()) return Qfalse;
  data->erase(pos);

  return Qtrue;
}

static VALUE exif_data_clear(VALUE self) {
  Exiv2::ExifData* data;
  Data_Get_Struct(self, Exiv2::ExifData, data);

  data->clear();

  return Qnil;
}


// Parse encoding from ISO 2022 encoding escape sequences, fall back to ISO 8859-1.

static rb_encoding *iptc_parse_encoding(Exiv2::IptcData *data) {
  Exiv2::IptcData::iterator pos = data->findKey(Exiv2::IptcKey("Iptc.Envelope.CharacterSet"));
  rb_encoding *encoding = rb_enc_find("ISO-8859-1");

  if (pos != data->end()) {
    const std::string value = pos->toString();

    if (pos->value().ok()) {
      if      (value == "\033%G" || value == "\033%/I")
        encoding = UTF_8;
      else if (value == "\033%/L")
        encoding = rb_enc_find("UTF-16");
      else if (value == "\033%/F")
        encoding = rb_enc_find("UTF-32");
      else if (value == "\033(B")
        encoding = rb_enc_find("US-ASCII");
      else if (value == "\033.A")
        encoding = rb_enc_find("ISO-8859-1");
      else if (value == "\033.B")
        encoding = rb_enc_find("ISO-8859-2");
      else if (value == "\033.C")
        encoding = rb_enc_find("ISO-8859-3");
      else if (value == "\033.D")
        encoding = rb_enc_find("ISO-8859-4");
      else if (value == "\033.F")
        encoding = rb_enc_find("ISO-8859-7");
      else if (value == "\033.G")
        encoding = rb_enc_find("ISO-8859-6");
      else if (value == "\033.H")
        encoding = rb_enc_find("ISO-8859-8");
      else if (value == "\033/b")
        encoding = rb_enc_find("ISO-8859-15");
    }
  }

  return encoding;
}

// Exiv2::IptcData methods

static VALUE iptc_data_each(VALUE self) {
  Exiv2::IptcData* data;
  Data_Get_Struct(self, Exiv2::IptcData, data);
  rb_encoding *encoding = iptc_parse_encoding(data);

  return metadata_each<Exiv2::IptcData>(self, encoding);
}

static VALUE iptc_data_add(VALUE self, VALUE key, VALUE value) {
  Exiv2::IptcData* data;
  Data_Get_Struct(self, Exiv2::IptcData, data);

  Exiv2::IptcKey iptcKey  = Exiv2::IptcKey(to_std_string(key));
  Exiv2::TypeId typeId    = Exiv2::IptcDataSets::dataSetType(iptcKey.tag(), iptcKey.record());

  Exiv2::Value::AutoPtr v = Exiv2::Value::create(typeId);
  v->read(value_to_std_string(value));

  if(data->add(iptcKey, v.get())) {
    return Qfalse;
  }
  return Qtrue;
}

static VALUE iptc_data_delete(VALUE self, VALUE key) {
  Exiv2::IptcData* data;
  Data_Get_Struct(self, Exiv2::IptcData, data);

  Exiv2::IptcKey iptcKey = Exiv2::IptcKey(to_std_string(key));
  Exiv2::IptcData::iterator pos = data->findKey(iptcKey);
  if(pos == data->end()) return Qfalse;
  data->erase(pos);

  return Qtrue;
}

static VALUE iptc_data_clear(VALUE self) {
  Exiv2::IptcData* data;
  Data_Get_Struct(self, Exiv2::IptcData, data);

  data->clear();

  return Qnil;
}

// Exiv2::XmpData methods

static VALUE xmp_data_each(VALUE self) {
  return metadata_each<Exiv2::XmpData>(self);
}

static VALUE xmp_data_add(VALUE self, VALUE key, VALUE value) {
  Exiv2::XmpData* data;
  Data_Get_Struct(self, Exiv2::XmpData, data);

  (*data)[to_std_string(key)] = value_to_std_string(value);

  return Qtrue;
}

static VALUE xmp_data_delete(VALUE self, VALUE key) {
  Exiv2::XmpData* data;
  Data_Get_Struct(self, Exiv2::XmpData, data);

  Exiv2::XmpKey xmpKey = Exiv2::XmpKey(to_std_string(key));
  Exiv2::XmpData::iterator pos = data->findKey(xmpKey);
  if(pos == data->end()) return Qfalse;
  data->erase(pos);

  return Qtrue;
}

static VALUE xmp_data_clear(VALUE self) {
  Exiv2::XmpData* data;
  Data_Get_Struct(self, Exiv2::XmpData, data);

  data->clear();

  return Qnil;
}
