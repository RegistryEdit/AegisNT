#pragma once

#include <cctype>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

enum class OptionRequired { Required, Optional, Advanced };

class Option {
public:
  Option(const std::string &DefaultValue, OptionRequired Required,
         const std::string &Description)
      : DefaultValue_(DefaultValue), Value_(DefaultValue), Required_(Required),
        Description_(Description) {}

  virtual ~Option() = default;

  virtual bool Validate(const std::string &Value) const = 0;
  virtual std::string TypeName() const = 0;

  void InternalSetName(const std::string &Name) { Name_ = Name; }

  const std::string &GetName() const { return Name_; }
  OptionRequired GetRequired() const { return Required_; }
  const std::string &GetDefaultValue() const { return DefaultValue_; }
  const std::string &GetValue() const { return Value_; }
  void SetValue(const std::string &Value) { Value_ = Value; }
  const std::string &GetDescription() const { return Description_; }
  bool IsEmpty() const { return Value_.empty(); }

protected:
  std::string Name_;
  std::string DefaultValue_;
  std::string Value_;
  OptionRequired Required_;
  std::string Description_;
};

class OptString : public Option {
public:
  OptString(const std::string &DefaultValue, OptionRequired Required,
            const std::string &Description)
      : Option(DefaultValue, Required, Description) {}

  bool Validate(const std::string &Value) const override { return true; }
  std::string TypeName() const override { return "OptString"; }
};

class OptBool : public Option {
public:
  OptBool(const std::string &DefaultValue, OptionRequired Required,
          const std::string &Description)
      : Option(DefaultValue, Required, Description) {}

  bool Validate(const std::string &Value) const override {
    std::string Lower;
    for (char C : Value)
      Lower += static_cast<char>(std::tolower(C));
    return Lower == "true" || Lower == "false" || Lower == "yes" ||
           Lower == "no";
  }
  std::string TypeName() const override { return "OptBool"; }
};

class OptInt : public Option {
public:
  OptInt(const std::string &DefaultValue, OptionRequired Required,
         const std::string &Description)
      : Option(DefaultValue, Required, Description) {}

  bool Validate(const std::string &Value) const override {
    if (Value.empty())
      return false;
    for (size_t I = 0; I < Value.size(); ++I) {
      if (I == 0 && Value[I] == '-')
        continue;
      if (!std::isdigit(static_cast<unsigned char>(Value[I])))
        return false;
    }
    return true;
  }
  std::string TypeName() const override { return "OptInt"; }
};

class OptPort : public Option {
public:
  OptPort(const std::string &DefaultValue, OptionRequired Required,
          const std::string &Description)
      : Option(DefaultValue, Required, Description) {}

  bool Validate(const std::string &Value) const override {
    try {
      int Port = std::stoi(Value);
      return Port >= 1 && Port <= 65535;
    } catch (...) {
      return false;
    }
  }
  std::string TypeName() const override { return "OptPort"; }
};

class OptAddress : public Option {
public:
  OptAddress(const std::string &DefaultValue, OptionRequired Required,
             const std::string &Description)
      : Option(DefaultValue, Required, Description) {}

  bool Validate(const std::string &Value) const override {
    if (Value.empty())
      return false;
    int Dots = 0;
    for (char C : Value) {
      if (C == '.')
        Dots++;
      else if (!std::isdigit(static_cast<unsigned char>(C)))
        return false;
    }
    return Dots == 3;
  }
  std::string TypeName() const override { return "OptAddress"; }
};

class OptAddressRange : public Option {
public:
  OptAddressRange(const std::string &DefaultValue, OptionRequired Required,
                  const std::string &Description)
      : Option(DefaultValue, Required, Description) {}

  bool Validate(const std::string &Value) const override {
    if (Value.empty())
      return false;
    size_t SlashPos = Value.find('/');
    if (SlashPos == std::string::npos)
      return false;
    OptAddress Addr("", OptionRequired::Optional, "");
    if (!Addr.Validate(Value.substr(0, SlashPos)))
      return false;
    OptInt Mask("", OptionRequired::Optional, "");
    return Mask.Validate(Value.substr(SlashPos + 1));
  }
  std::string TypeName() const override { return "OptAddressRange"; }
};

class OptPath : public Option {
public:
  OptPath(const std::string &DefaultValue, OptionRequired Required,
          const std::string &Description)
      : Option(DefaultValue, Required, Description) {}

  bool Validate(const std::string &Value) const override {
    return !Value.empty();
  }
  std::string TypeName() const override { return "OptPath"; }
};

class OptEnum : public Option {
public:
  OptEnum(const std::vector<std::string> &Choices,
          const std::string &DefaultValue, OptionRequired Required,
          const std::string &Description)
      : Option(DefaultValue, Required, Description), Choices_(Choices) {}

  bool Validate(const std::string &Value) const override {
    for (const auto &C : Choices_)
      if (C == Value)
        return true;
    return false;
  }
  std::string TypeName() const override { return "OptEnum"; }
  const std::vector<std::string> &GetChoices() const { return Choices_; }

private:
  std::vector<std::string> Choices_;
};
