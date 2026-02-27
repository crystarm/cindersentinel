with Ada.Command_Line;
with Ada.Text_IO;
with Ada.Streams;
with Ada.Streams.Stream_IO;
with Ada.Strings.Unbounded;

procedure Cindersentinel_Aegis is
   use Ada.Command_Line;
   use Ada.Text_IO;
   use Ada.Strings.Unbounded;
   use Ada.Streams;

   -- Limits (keep in sync with C++ validator)
   Max_Bytes                 : constant Natural := 1_048_576;
   Max_Items                 : constant Natural := 262_144;
   Max_Depth                 : constant Natural := 64;
   Max_Rules                 : constant Natural := 4096;
   Max_Ranges_Per_Proto      : constant Natural := 4096;
   Max_Expanded_Per_Proto    : constant Natural := 200_000;
   Max_Total_Ops             : constant Natural := 200_000;

   -- policy/keys.h equivalents
   CSK_KIND            : constant Unsigned_64 := 1;
   CSK_V               : constant Unsigned_64 := 2;
   CSK_DEFAULT_ACTION  : constant Unsigned_64 := 3;
   CSK_RULES           : constant Unsigned_64 := 4;

   CSR_ACTION          : constant Unsigned_64 := 1;
   CSR_PROTO           : constant Unsigned_64 := 2;
   CSR_DPORTS          : constant Unsigned_64 := 3;

   CSA_LET             : constant Unsigned_64 := 0;
   CSA_FORBID          : constant Unsigned_64 := 1;

   CSP_ICMP            : constant Unsigned_64 := 1;
   CSP_TCP             : constant Unsigned_64 := 2;
   CSP_UDP             : constant Unsigned_64 := 3;

   type Range is record
      Lo : Unsigned_16;
      Hi : Unsigned_16;
   end record;

   type Range_Array is array (Positive range <>) of Range;

   type Range_List is record
      Data : Range_Array (1 .. Max_Ranges_Per_Proto);
      Len  : Natural := 0;
   end record;

   procedure Append_Range (L : in out Range_List; R : Range) is
   begin
      if L.Len >= Max_Ranges_Per_Proto then
         raise Program_Error with "too many ranges";
      end if;
      L.Len := L.Len + 1;
      L.Data (L.Len) := R;
   end Append_Range;

   procedure Fail (Msg : String; Code : Integer := 2) is
   begin
      Put_Line (Standard_Error, "aegis: " & Msg);
      Set_Exit_Status (Exit_Status (Code));
      raise Program_Error;
   end Fail;

   type Byte_Array is array (Natural range <>) of Unsigned_8;

   function Read_File (Path : String) return Byte_Array is
      F : Ada.Streams.Stream_IO.File_Type;
      S : Stream_Element_Array (1 .. Max_Bytes);
      Last : Stream_Element_Offset;
   begin
      Ada.Streams.Stream_IO.Open (F, Ada.Streams.Stream_IO.In_File, Path);
      Ada.Streams.Stream_IO.Read (F, S, Last);
      Ada.Streams.Stream_IO.Close (F);

      declare
         Len : constant Natural := Natural (Last);
         B   : Byte_Array (0 .. Len - 1);
      begin
         for I in 0 .. Len - 1 loop
            B (I) := Unsigned_8 (S (Stream_Element_Offset (I + 1)));
         end loop;
         return B;
      end;
   exception
      when others =>
         Fail ("cannot open file: " & Path);
         return (0 .. 0 => 0);
   end Read_File;

   type Parser is record
      Buf       : Byte_Array (0 .. 0);
      Pos       : Natural := 0;
      Items     : Natural := 0;
      Depth     : Natural := 0;
   end record;

   procedure Ensure (P : in Parser; Need : Natural) is
   begin
      if P.Pos + Need > P.Buf'Length then
         Fail ("CBOR decode error: truncated bytes/text");
      end if;
   end Ensure;

   function Read_U8 (P : in out Parser) return Unsigned_8 is
   begin
      Ensure (P, 1);
      P.Pos := P.Pos + 1;
      return P.Buf (P.Pos - 1);
   end Read_U8;

   function Read_U16 (P : in out Parser) return Unsigned_16 is
      B1, B2 : Unsigned_8;
   begin
      B1 := Read_U8 (P);
      B2 := Read_U8 (P);
      return Unsigned_16 (B1) * 256 + Unsigned_16 (B2);
   end Read_U16;

   function Read_U32 (P : in out Parser) return Unsigned_32 is
      B1, B2, B3, B4 : Unsigned_8;
   begin
      B1 := Read_U8 (P);
      B2 := Read_U8 (P);
      B3 := Read_U8 (P);
      B4 := Read_U8 (P);
      return Unsigned_32 (B1) * 16#1000000# +
             Unsigned_32 (B2) * 16#10000# +
             Unsigned_32 (B3) * 16#100# +
             Unsigned_32 (B4);
   end Read_U32;

   function Read_U64 (P : in out Parser) return Unsigned_64 is
      Hi, Lo : Unsigned_32;
   begin
      Hi := Read_U32 (P);
      Lo := Read_U32 (P);
      return Unsigned_64 (Hi) * 16#1_0000_0000# + Unsigned_64 (Lo);
   end Read_U64;

   function Read_Unsigned (P : in out Parser; Add_Info : Unsigned_8) return Unsigned_64 is
   begin
      if Add_Info < 24 then
         return Unsigned_64 (Add_Info);
      elsif Add_Info = 24 then
         return Unsigned_64 (Read_U8 (P));
      elsif Add_Info = 25 then
         return Unsigned_64 (Read_U16 (P));
      elsif Add_Info = 26 then
         return Unsigned_64 (Read_U32 (P));
      elsif Add_Info = 27 then
         return Read_U64 (P);
      else
         Fail ("CBOR decode error: indefinite length or invalid integer");
         return 0;
      end if;
   end Read_Unsigned;

   procedure Enter_Node (P : in out Parser) is
   begin
      P.Items := P.Items + 1;
      if P.Items > Max_Items then
         Fail ("CBOR decode error: too many items");
      end if;
   end Enter_Node;

   function Peek_Major (P : in Parser) return Unsigned_8 is
   begin
      if P.Pos >= P.Buf'Length then
         Fail ("CBOR decode error: truncated");
      end if;
      return P.Buf (P.Pos) / 32;
   end Peek_Major;

   function Read_Head (P : in out Parser; Major : Unsigned_8) return Unsigned_64 is
      B  : Unsigned_8;
      M  : Unsigned_8;
      AI : Unsigned_8;
   begin
      Enter_Node (P);
      B := Read_U8 (P);
      M := B / 32;
      AI := B mod 32;
      if M /= Major then
         Fail ("CBOR decode error: unexpected type");
      end if;
      return Read_Unsigned (P, AI);
   end Read_Head;

   function Read_UInt (P : in out Parser) return Unsigned_64 is
      B : Unsigned_8;
      M : Unsigned_8;
      AI : Unsigned_8;
   begin
      Enter_Node (P);
      B := Read_U8 (P);
      M := B / 32;
      AI := B mod 32;
      if M /= 0 then
         Fail ("CBOR decode error: expected uint");
      end if;
      return Read_Unsigned (P, AI);
   end Read_UInt;

   function Read_Text (P : in out Parser) return String is
      Len : Unsigned_64;
   begin
      Len := Read_Head (P, 3);
      if Len > Unsigned_64 (Max_Bytes) then
         Fail ("CBOR decode error: text too large");
      end if;

      Ensure (P, Natural (Len));
      declare
         S : String (1 .. Integer (Len));
      begin
         for I in 1 .. Integer (Len) loop
            S (I) := Character'Val (P.Buf (P.Pos));
            P.Pos := P.Pos + 1;
         end loop;
         return S;
      end;
   end Read_Text;

   function Read_Array_Len (P : in out Parser) return Natural is
      Len64 : Unsigned_64;
   begin
      Len64 := Read_Head (P, 4);
      if Len64 > Unsigned_64 (Max_Items) then
         Fail ("CBOR decode error: array too large");
      end if;
      return Natural (Len64);
   end Read_Array_Len;

   function Read_Map_Len (P : in out Parser) return Natural is
      Len64 : Unsigned_64;
   begin
      Len64 := Read_Head (P, 5);
      if Len64 > Unsigned_64 (Max_Items) then
         Fail ("CBOR decode error: map too large");
      end if;
      return Natural (Len64);
   end Read_Map_Len;

   procedure Inc_Depth (P : in out Parser) is
   begin
      P.Depth := P.Depth + 1;
      if P.Depth > Max_Depth then
         Fail ("CBOR decode error: too deep");
      end if;
   end Inc_Depth;

   procedure Dec_Depth (P : in out Parser) is
   begin
      if P.Depth > 0 then
         P.Depth := P.Depth - 1;
      end if;
   end Dec_Depth;

   procedure Validate_Rules (P : in out Parser; Rules_Len : Natural;
                             Tcp : in out Range_List; Udp : in out Range_List;
                             Total_Rules : in out Natural) is
   begin
      Inc_Depth (P);
      for I in 1 .. Rules_Len loop
         if Total_Rules >= Max_Rules then
            Fail ("too many rules");
         end if;
         Total_Rules := Total_Rules + 1;

         -- Each rule is a map
         if Peek_Major (P) /= 5 then
            Fail ("rule must be map");
         end if;

         declare
            Rule_Len : constant Natural := Read_Map_Len (P);
            Last_Key : Unsigned_64 := 0;
            Have_Key : Boolean := False;
            Action   : Unsigned_64 := 0;
            Proto    : Unsigned_64 := 0;
            Has_Action : Boolean := False;
            Has_Proto  : Boolean := False;
            Has_Dports : Boolean := False;
         begin
            Inc_Depth (P);
            for K in 1 .. Rule_Len loop
               declare
                  Key : constant Unsigned_64 := Read_UInt (P);
               begin
                  if Have_Key and then Key <= Last_Key then
                     Fail ("duplicate or unsorted map key");
                  end if;
                  Have_Key := True;
                  Last_Key := Key;

                  if Key = CSR_ACTION then
                     Action := Read_UInt (P);
                     Has_Action := True;
                  elsif Key = CSR_PROTO then
                     Proto := Read_UInt (P);
                     Has_Proto := True;
                  elsif Key = CSR_DPORTS then
                     Has_Dports := True;
                     -- dports array
                     if Peek_Major (P) /= 4 then
                        Fail ("dports must be array");
                     end if;
                     declare
                        DLen : constant Natural := Read_Array_Len (P);
                     begin
                        if DLen = 0 then
                           -- allow empty for icmp check later
                           null;
                        end if;

                        Inc_Depth (P);
                        for J in 1 .. DLen loop
                           if Peek_Major (P) = 0 then
                              declare
                                 Port : constant Unsigned_64 := Read_UInt (P);
                              begin
                                 if Port < 1 or else Port > 65535 then
                                    Fail ("port out of range");
                                 end if;
                                 if Proto = CSP_TCP then
                                    Append_Range (Tcp, (Unsigned_16 (Port), Unsigned_16 (Port)));
                                 elsif Proto = CSP_UDP then
                                    Append_Range (Udp, (Unsigned_16 (Port), Unsigned_16 (Port)));
                                 end if;
                              end;
                           elsif Peek_Major (P) = 4 then
                              declare
                                 Pair_Len : constant Natural := Read_Array_Len (P);
                              begin
                                 if Pair_Len /= 2 then
                                    Fail ("port range must be [lo, hi]");
                                 end if;

                                 declare
                                    Lo : constant Unsigned_64 := Read_UInt (P);
                                    Hi : constant Unsigned_64 := Read_UInt (P);
                                 begin
                                    if Lo < 1 or else Hi < 1 or else Lo > 65535 or else Hi > 65535 or else Lo > Hi then
                                       Fail ("bad port range");
                                    end if;
                                    if Proto = CSP_TCP then
                                       Append_Range (Tcp, (Unsigned_16 (Lo), Unsigned_16 (Hi)));
                                    elsif Proto = CSP_UDP then
                                       Append_Range (Udp, (Unsigned_16 (Lo), Unsigned_16 (Hi)));
                                    end if;
                                 end;
                              end;
                           else
                              Fail ("dports elements must be uint or [lo,hi]");
                           end if;
                        end loop;
                        Dec_Depth (P);
                     end;
                  else
                     -- unknown field
                     Fail ("unknown rule field");
                  end if;
               end;
            end loop;
            Dec_Depth (P);

            if not Has_Action or else not Has_Proto then
               Fail ("rule must contain action and proto");
            end if;

            if Action = CSA_LET then
               Fail ("'let' in rules is unsupported for now");
            elsif Action /= CSA_FORBID then
               Fail ("unknown action");
            end if;

            if Proto /= CSP_ICMP and then Proto /= CSP_TCP and then Proto /= CSP_UDP then
               Fail ("unknown proto");
            end if;

            if Proto = CSP_ICMP then
               if Has_Dports then
                  -- allow only empty array earlier; if non-empty, we would have added ranges
                  null;
               end if;
            else
               if not Has_Dports then
                  Fail ("tcp/udp rule must have dports");
               end if;
            end if;
         end;
      end loop;
      Dec_Depth (P);
   end Validate_Rules;

   procedure Sort_And_Check (L : in out Range_List; Label : String; Expanded_Limit : Natural; Total_Ops : in out Natural) is
   begin
      if L.Len = 0 then
         return;
      end if;

      -- simple insertion sort (Len bounded)
      for I in 2 .. L.Len loop
         declare
            Key : Range := L.Data (I);
            J : Integer := I - 1;
         begin
            while J >= 1 loop
               exit when (L.Data (J).Lo < Key.Lo) or else
                         (L.Data (J).Lo = Key.Lo and then L.Data (J).Hi <= Key.Hi);
               L.Data (J + 1) := L.Data (J);
               J := J - 1;
            end loop;
            L.Data (J + 1) := Key;
         end;
      end loop;

      -- overlap check + expanded count
      declare
         Prev_Hi : Unsigned_16 := L.Data (1).Hi;
         Count   : Unsigned_64 := Unsigned_64 (L.Data (1).Hi) - Unsigned_64 (L.Data (1).Lo) + 1;
      begin
         for I in 2 .. L.Len loop
            if L.Data (I).Lo <= Prev_Hi then
               Fail ("conflicting " & Label & " ranges (overlap)");
            end if;
            Prev_Hi := L.Data (I).Hi;
            Count := Count + Unsigned_64 (L.Data (I).Hi) - Unsigned_64 (L.Data (I).Lo) + 1;
            if Count > Unsigned_64 (Expanded_Limit) then
               Fail ("policy too wide: expanded ports exceed per-proto limit");
            end if;
         end loop;

         Total_Ops := Total_Ops + Natural (Count);
         if Total_Ops > Max_Total_Ops then
            Fail ("policy too wide: total ops exceed limit");
         end if;
      end;
   end Sort_And_Check;

begin
   if Argument_Count /= 1 then
      Put_Line (Standard_Error, "usage: cindersentinel-aegis <policy.cbor>");
      Set_Exit_Status (Exit_Status (2));
      return;
   end if;

   declare
      Path : constant String := Argument (1);
      Buf  : Byte_Array := Read_File (Path);
      P    : Parser := (Buf => Buf, Pos => 0, Items => 0, Depth => 0);
      Root_Len : Natural;
      Last_Key : Unsigned_64 := 0;
      Have_Key : Boolean := False;

      Kind : Unbounded_String := To_Unbounded_String ("");
      V    : Unsigned_64 := 0;
      Has_Kind : Boolean := False;
      Has_V    : Boolean := False;
      Has_Rules: Boolean := False;
      Def_Action : Unsigned_64 := 0;
      Has_Def : Boolean := False;

      Tcp : Range_List;
      Udp : Range_List;
      Rules_Count : Natural := 0;
   begin
      if P.Buf'Length = 0 then
         Fail ("invalid input: empty policy");
      end if;

      if Peek_Major (P) /= 5 then
         Fail ("policy root must be map");
      end if;

      Root_Len := Read_Map_Len (P);

      Inc_Depth (P);
      for I in 1 .. Root_Len loop
         declare
            Key : constant Unsigned_64 := Read_UInt (P);
         begin
            if Have_Key and then Key <= Last_Key then
               Fail ("duplicate or unsorted map key");
            end if;
            Have_Key := True;
            Last_Key := Key;

            if Key = CSK_KIND then
               Kind := To_Unbounded_String (Read_Text (P));
               Has_Kind := True;
            elsif Key = CSK_V then
               V := Read_UInt (P);
               Has_V := True;
            elsif Key = CSK_DEFAULT_ACTION then
               Def_Action := Read_UInt (P);
               Has_Def := True;
            elsif Key = CSK_RULES then
               if Peek_Major (P) /= 4 then
                  Fail ("rules must be array");
               end if;
               declare
                  Rules_Len : constant Natural := Read_Array_Len (P);
               begin
                  Has_Rules := True;
                  if Rules_Len > Max_Rules then
                     Fail ("too many rules");
                  end if;
                  Validate_Rules (P, Rules_Len, Tcp, Udp, Rules_Count);
               end;
            else
               Fail ("unknown root field");
            end if;
         end;
      end loop;
      Dec_Depth (P);

      if not Has_Kind or else not Has_V or else not Has_Rules then
         Fail ("missing required root fields");
      end if;

      if To_String (Kind) /= "cindersentinel.policy" then
         Fail ("unexpected kind");
      end if;

      if V /= 1 then
         Fail ("unsupported policy version");
      end if;

      if Has_Def and then Def_Action /= CSA_LET then
         Fail ("default_action forbid unsupported for now");
      end if;

      -- Range conflicts & width
      declare
         Total_Ops : Natural := 0;
      begin
         Sort_And_Check (Tcp, "tcp", Max_Expanded_Per_Proto, Total_Ops);
         Sort_And_Check (Udp, "udp", Max_Expanded_Per_Proto, Total_Ops);
      end;

      if P.Pos /= P.Buf'Length then
         Fail ("trailing bytes after top-level CBOR value");
      end if;
   end;

   Put_Line ("OK");
   Set_Exit_Status (Exit_Status (0));

exception
   when Program_Error =>
      null;
   when others =>
      Put_Line (Standard_Error, "aegis: unexpected error");
      Set_Exit_Status (Exit_Status (2));
end Cindersentinel_Aegis;